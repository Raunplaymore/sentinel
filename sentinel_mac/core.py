#!/usr/bin/env python3
"""
Sentinel — AI Session Guardian for macOS
Monitors system resources and sends smart alerts via ntfy.sh
"""

import psutil
import subprocess
import requests
import yaml
import time
import json
import logging
import signal
import sys
import os
import re
import fcntl
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from typing import Optional

# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class SystemMetrics:
    timestamp: datetime
    # CPU
    cpu_percent: float = 0.0
    cpu_temp: Optional[float] = None
    thermal_pressure: str = "nominal"
    # Memory
    memory_percent: float = 0.0
    memory_used_gb: float = 0.0
    # Battery
    battery_percent: Optional[float] = None
    battery_plugged: bool = True
    battery_minutes_left: Optional[int] = None
    battery_cycle_count: Optional[int] = None
    # Fan
    fan_speed_rpm: Optional[int] = None
    # Disk
    disk_percent: float = 0.0
    disk_free_gb: float = 0.0
    # Network
    net_sent_mb: float = 0.0
    net_recv_mb: float = 0.0
    # AI Processes
    ai_processes: list = field(default_factory=list)
    ai_cpu_total: float = 0.0
    ai_memory_total_mb: float = 0.0


@dataclass
class Alert:
    level: str          # critical, warning, info
    category: str       # battery, thermal, process, network, session
    title: str
    message: str
    emoji: str = "⚠️"
    priority: int = 3   # ntfy: 1=min, 3=default, 5=urgent


# ─────────────────────────────────────────────
# Config Resolution
# ─────────────────────────────────────────────

DEFAULT_CONFIG = {
    "ntfy_topic": "sentinel-default",
    "ntfy_server": "https://ntfy.sh",
    "notifications_enabled": True,
    "check_interval_seconds": 30,
    "status_interval_minutes": 60,
    "cooldown_minutes": 10,
    "thresholds": {
        "battery_warning": 20,
        "battery_critical": 10,
        "battery_drain_rate": 10,
        "temp_warning": 85,
        "temp_critical": 95,
        "memory_critical": 90,
        "network_spike_mb": 100,
        "session_hours_warning": 3,
        "disk_critical": 90,
    }
}


def resolve_config_path(explicit_path: str = None) -> Path:
    """Find config file in priority order:
    1. Explicit --config path
    2. ./config.yaml (current directory)
    3. ~/.config/sentinel/config.yaml (XDG-style)
    4. None (use defaults)
    """
    if explicit_path:
        return Path(explicit_path)

    # Current directory
    cwd_config = Path.cwd() / "config.yaml"
    if cwd_config.exists():
        return cwd_config

    # XDG config
    xdg_config = Path.home() / ".config" / "sentinel" / "config.yaml"
    if xdg_config.exists():
        return xdg_config

    return None


def resolve_data_dir() -> Path:
    """Resolve data directory for logs and lock files.
    Uses ~/.local/share/sentinel/ for pip installs,
    or ./logs/ if running from repo directory.
    """
    # If running from repo (install.sh style), use local logs/
    local_logs = Path.cwd() / "logs"
    if local_logs.exists():
        return local_logs

    # XDG data dir
    data_dir = Path.home() / ".local" / "share" / "sentinel"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def load_config(config_path: Path = None) -> dict:
    """Load config with error handling and default fallback."""
    defaults = DEFAULT_CONFIG.copy()
    defaults["thresholds"] = DEFAULT_CONFIG["thresholds"].copy()

    if config_path is None:
        return defaults

    try:
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}
        merged = {**defaults, **user_config}
        merged["thresholds"] = {**defaults["thresholds"], **user_config.get("thresholds", {})}
        return merged
    except FileNotFoundError:
        logging.warning(f"Config not found: {config_path} — using defaults")
        return defaults
    except yaml.YAMLError as e:
        logging.error(f"Config parse error: {e} — using defaults")
        return defaults


# ─────────────────────────────────────────────
# Metric Collectors (macOS-specific)
# ─────────────────────────────────────────────

class MacOSCollector:
    """Collects system metrics using macOS native tools + psutil."""

    # Only match process names that are unambiguously AI-related
    AI_PROCESS_NAMES = {
        "ollama", "llamaserver", "mlx_lm",
    }

    # Match these keywords in the full command line (more precise)
    AI_CMDLINE_KEYWORDS = [
        "claude", "openai", "anthropic", "langchain",
        "llama", "ollama", "transformers", "torch",
        "jupyter", "notebook", "mlx_lm", "stable-diffusion",
        "diffusers", "vllm", "text-generation",
    ]

    # Generic names that need cmdline keyword confirmation
    GENERIC_PROCESS_NAMES = {
        "node", "python", "python3", "code", "cursor", "docker",
    }

    def __init__(self):
        self._prev_net = psutil.net_io_counters()
        self._prev_net_time = time.time()

    def collect(self) -> SystemMetrics:
        m = SystemMetrics(timestamp=datetime.now())

        # CPU
        m.cpu_percent = psutil.cpu_percent(interval=1)
        m.cpu_temp = self._get_cpu_temp()
        m.thermal_pressure = self._get_thermal_pressure()

        # Memory
        mem = psutil.virtual_memory()
        m.memory_percent = mem.percent
        m.memory_used_gb = round(mem.used / (1024**3), 1)

        # Disk (root volume)
        disk = psutil.disk_usage("/")
        m.disk_percent = disk.percent
        m.disk_free_gb = round(disk.free / (1024**3), 1)

        # Battery
        bat = psutil.sensors_battery()
        if bat:
            m.battery_percent = round(bat.percent, 1)
            m.battery_plugged = bat.power_plugged
            if bat.secsleft > 0 and bat.secsleft != psutil.POWER_TIME_UNLIMITED:
                m.battery_minutes_left = int(bat.secsleft / 60)
        m.battery_cycle_count = self._get_battery_cycle_count()

        # Fan
        m.fan_speed_rpm = self._get_fan_speed()

        # Network delta
        net_now = psutil.net_io_counters()
        now = time.time()
        dt = now - self._prev_net_time
        if dt > 0:
            m.net_sent_mb = round((net_now.bytes_sent - self._prev_net.bytes_sent) / (1024**2), 2)
            m.net_recv_mb = round((net_now.bytes_recv - self._prev_net.bytes_recv) / (1024**2), 2)
        self._prev_net = net_now
        self._prev_net_time = now

        # AI Processes
        m.ai_processes = self._get_ai_processes()
        m.ai_cpu_total = sum(p["cpu"] for p in m.ai_processes)
        m.ai_memory_total_mb = sum(p["mem_mb"] for p in m.ai_processes)

        return m

    def _get_cpu_temp(self) -> Optional[float]:
        """Get CPU temperature via osx-cpu-temp (brew install osx-cpu-temp)."""
        try:
            out = subprocess.run(
                ["osx-cpu-temp"], capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0:
                match = re.search(r"([\d.]+)°C", out.stdout)
                if match:
                    return float(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def _get_thermal_pressure(self) -> str:
        """Get macOS thermal pressure level."""
        try:
            out = subprocess.run(
                ["pmset", "-g", "therm"], capture_output=True, text=True, timeout=3
            )
            if "sleeping" in out.stdout.lower():
                return "critical"
            for line in out.stdout.splitlines():
                if "CPU_Speed_Limit" in line:
                    match = re.search(r"(\d+)", line)
                    if match:
                        limit = int(match.group(1))
                        if limit < 50:
                            return "critical"
                        elif limit < 80:
                            return "serious"
                        elif limit < 100:
                            return "moderate"
            return "nominal"
        except Exception:
            return "unknown"

    def _get_battery_cycle_count(self) -> Optional[int]:
        try:
            out = subprocess.run(
                ["ioreg", "-r", "-c", "AppleSmartBattery"],
                capture_output=True, text=True, timeout=3
            )
            match = re.search(r'"CycleCount"\s*=\s*(\d+)', out.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _get_fan_speed(self) -> Optional[int]:
        try:
            out = subprocess.run(
                ["ioreg", "-r", "-c", "AppleSMCFanControl"],
                capture_output=True, text=True, timeout=3
            )
            match = re.search(r'"CurrentSpeed"\s*=\s*(\d+)', out.stdout)
            if match:
                return int(match.group(1))
            match = re.search(r'"ActualSpeed"\s*=\s*(\d+)', out.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _get_ai_processes(self) -> list:
        """Identify AI-related processes and their resource usage.

        Uses a three-tier detection strategy:
        - Tier 1: Process names that are unambiguously AI (ollama, llamaserver, etc.)
        - Tier 2: Generic process names (python, node) that require AI keyword
                   confirmation in their command line arguments.
        - Tier 3: Any process with AI keyword in cmdline.
        """
        ai_procs = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                cmdline = " ".join(info["cmdline"] or []).lower()

                is_ai = name in self.AI_PROCESS_NAMES

                if not is_ai and name in self.GENERIC_PROCESS_NAMES:
                    is_ai = any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS)

                if not is_ai:
                    is_ai = any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS)

                if is_ai and (info["cpu_percent"] or 0) > 5.0:
                    mem_mb = round((info["memory_info"].rss if info["memory_info"] else 0) / (1024**2), 1)
                    ai_procs.append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "cpu": round(info["cpu_percent"] or 0, 1),
                        "mem_mb": mem_mb,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(ai_procs, key=lambda p: p["cpu"], reverse=True)[:10]


# ─────────────────────────────────────────────
# Alert Engine
# ─────────────────────────────────────────────

class AlertEngine:
    """Evaluates composite conditions and generates smart alerts."""

    def __init__(self, config: dict):
        self.config = config
        self.thresholds = config.get("thresholds", {})
        self._cooldowns: dict[str, datetime] = {}
        self._cooldown_minutes = config.get("cooldown_minutes", 10)
        self._history: deque = deque(maxlen=30)
        self._session_start: Optional[datetime] = None
        self._idle_start: Optional[datetime] = None

    def evaluate(self, m: SystemMetrics) -> list[Alert]:
        self._history.append(m)
        alerts = []

        # ── Battery Alerts ──
        if m.battery_percent is not None:
            if not m.battery_plugged:
                if m.battery_percent <= self.thresholds.get("battery_critical", 10):
                    alerts.append(Alert(
                        level="critical", category="battery_critical",
                        title="🪫 배터리 위험",
                        message=f"배터리 {m.battery_percent}% — 충전기 연결 필요!\n"
                               f"{'예상 ' + str(m.battery_minutes_left) + '분 남음' if m.battery_minutes_left else ''}",
                        emoji="🔴", priority=5
                    ))
                elif m.battery_percent <= self.thresholds.get("battery_warning", 20):
                    time_msg = f"\n예상 {m.battery_minutes_left}분 남음" if m.battery_minutes_left else ""
                    ai_msg = f"\nAI 프로세스 {len(m.ai_processes)}개 실행 중" if m.ai_processes else ""
                    alerts.append(Alert(
                        level="warning", category="battery_warning",
                        title="🔋 배터리 부족",
                        message=f"배터리 {m.battery_percent}%, 충전기 미연결{time_msg}{ai_msg}",
                        emoji="🟠", priority=4
                    ))

                # Rapid drain detection (time-based: %/hour)
                if len(self._history) >= 3:
                    oldest = self._history[0]
                    elapsed_hours = (m.timestamp - oldest.timestamp).total_seconds() / 3600
                    if elapsed_hours > 0.01:
                        drain_total = (oldest.battery_percent or 0) - (m.battery_percent or 0)
                        drain_per_hour = drain_total / elapsed_hours
                        threshold = self.thresholds.get("battery_drain_rate", 10)
                        if drain_per_hour > threshold:
                            alerts.append(Alert(
                                level="warning", category="battery_drain",
                                title="⚡ 배터리 급속 소모",
                                message=f"소모 속도: {drain_per_hour:.1f}%/시간\n"
                                       f"({elapsed_hours * 60:.0f}분간 {drain_total:.1f}% 감소)\n"
                                       f"AI CPU 사용: {m.ai_cpu_total:.0f}%",
                                emoji="🟠", priority=4
                            ))

        # ── Thermal Alerts ──
        if m.cpu_temp is not None:
            if m.cpu_temp >= self.thresholds.get("temp_critical", 95):
                alerts.append(Alert(
                    level="critical", category="temp_critical",
                    title="🌡️ CPU 과열 위험!",
                    message=f"CPU 온도 {m.cpu_temp}°C — 쓰로틀링 발생 중\n"
                           f"Thermal: {m.thermal_pressure}\n"
                           f"{'팬 ' + str(m.fan_speed_rpm) + ' RPM' if m.fan_speed_rpm else ''}",
                    emoji="🔴", priority=5
                ))
            elif m.cpu_temp >= self.thresholds.get("temp_warning", 85):
                alerts.append(Alert(
                    level="warning", category="temp_warning",
                    title="🌡️ CPU 온도 높음",
                    message=f"CPU {m.cpu_temp}°C | 팬 {m.fan_speed_rpm or '?'} RPM\n"
                           f"CPU 사용률 {m.cpu_percent}%",
                    emoji="🟠", priority=3
                ))

        elif m.thermal_pressure in ("critical", "serious"):
            alerts.append(Alert(
                level="warning", category="thermal_pressure",
                title="🌡️ 시스템 쓰로틀링 감지",
                message=f"Thermal pressure: {m.thermal_pressure}\n"
                       f"CPU {m.cpu_percent}% | 메모리 {m.memory_percent}%",
                emoji="🟠", priority=4
            ))

        # ── Memory Alerts ──
        if m.memory_percent >= self.thresholds.get("memory_critical", 90):
            alerts.append(Alert(
                level="warning", category="memory_high",
                title="💾 메모리 부족",
                message=f"메모리 {m.memory_percent}% 사용 ({m.memory_used_gb}GB)\n"
                       f"AI 프로세스: {m.ai_memory_total_mb:.0f}MB 점유",
                emoji="🟠", priority=4
            ))

        # ── AI Process Alerts ──
        if m.ai_processes:
            if self._session_start is None:
                self._session_start = m.timestamp
                self._idle_start = None

            if self._session_start:
                duration = (m.timestamp - self._session_start).total_seconds() / 3600
                session_limit = self.thresholds.get("session_hours_warning", 3)
                if duration >= session_limit:
                    top = m.ai_processes[0]
                    alerts.append(Alert(
                        level="info", category="long_session",
                        title="⏰ 장시간 AI 세션",
                        message=f"AI 세션 {duration:.1f}시간 경과\n"
                               f"Top: {top['name']} (CPU {top['cpu']}%, MEM {top['mem_mb']}MB)",
                        emoji="🟡", priority=3
                    ))

            if len(self._history) >= 5:
                recent = list(self._history)[-5:]
                avg_cpu = sum(h.ai_cpu_total for h in recent) / len(recent)
                avg_net = sum(h.net_sent_mb + h.net_recv_mb for h in recent) / len(recent)
                if avg_cpu > 50 and avg_net < 0.1:
                    alerts.append(Alert(
                        level="warning", category="stuck_process",
                        title="🔄 프로세스 멈춤 의심",
                        message=f"AI 프로세스 CPU {avg_cpu:.0f}% 사용 중이나\n"
                               f"네트워크 I/O 거의 없음 — 무한루프 가능성",
                        emoji="🟠", priority=4
                    ))

        else:
            if self._session_start:
                duration = (m.timestamp - self._session_start).total_seconds() / 60
                if duration > 5:
                    alerts.append(Alert(
                        level="info", category="session_end",
                        title="✅ AI 세션 종료",
                        message=f"세션 시간: {duration:.0f}분",
                        emoji="✅", priority=2
                    ))
                self._session_start = None

            self._idle_start = self._idle_start or m.timestamp

        # ── Night Watch ──
        hour = m.timestamp.hour
        if (0 <= hour <= 6) and m.ai_processes and not m.battery_plugged:
            alerts.append(Alert(
                level="warning", category="night_watch",
                title="🌙 야간 방치 감지",
                message=f"새벽 {hour}시 — AI 세션 활성 + 배터리 {m.battery_percent}%\n"
                       f"충전기 미연결 상태",
                emoji="🟡", priority=4
            ))

        # ── Disk Alert ──
        disk_threshold = self.thresholds.get("disk_critical", 90)
        if m.disk_percent >= disk_threshold:
            alerts.append(Alert(
                level="warning", category="disk_high",
                title="💿 디스크 공간 부족",
                message=f"디스크 사용률 {m.disk_percent}%\n"
                       f"남은 공간: {m.disk_free_gb}GB",
                emoji="🟠", priority=4
            ))

        # ── Network Spike ──
        total_mb = m.net_sent_mb + m.net_recv_mb
        net_threshold = self.thresholds.get("network_spike_mb", 100)
        if total_mb > net_threshold:
            alerts.append(Alert(
                level="info", category="network_spike",
                title="📡 네트워크 트래픽 급증",
                message=f"이번 간격: ↑{m.net_sent_mb:.1f}MB ↓{m.net_recv_mb:.1f}MB\n"
                       f"총 {total_mb:.1f}MB",
                emoji="🟡", priority=3
            ))

        return self._apply_cooldowns(alerts)

    def _apply_cooldowns(self, alerts: list[Alert]) -> list[Alert]:
        """Prevent alert spam by enforcing cooldown per category."""
        now = datetime.now()
        filtered = []
        for alert in alerts:
            last = self._cooldowns.get(alert.category)
            cooldown = self._cooldown_minutes
            if alert.level == "critical":
                cooldown = max(2, cooldown // 3)

            if last is None or (now - last).total_seconds() > cooldown * 60:
                filtered.append(alert)
                self._cooldowns[alert.category] = now
        return filtered


# ─────────────────────────────────────────────
# Notifier
# ─────────────────────────────────────────────

class NtfyNotifier:
    """Sends push notifications via ntfy.sh with retry queue."""

    PRIORITY_MAP = {1: "min", 2: "low", 3: "default", 4: "high", 5: "urgent"}
    MAX_RETRIES = 3
    RETRY_QUEUE_SIZE = 50

    def __init__(self, config: dict):
        self.topic = config.get("ntfy_topic", "sentinel-default")
        self.server = config.get("ntfy_server", "https://ntfy.sh")
        self.enabled = config.get("notifications_enabled", True)
        self._retry_queue: deque = deque(maxlen=self.RETRY_QUEUE_SIZE)

    def send(self, alert: Alert):
        if not self.enabled:
            return

        self._flush_retries()

        if not self._do_send(alert):
            self._retry_queue.append((alert, 1))

    def _do_send(self, alert: Alert) -> bool:
        url = f"{self.server}/{self.topic}"
        headers = {
            "Title": alert.title,
            "Priority": self.PRIORITY_MAP.get(alert.priority, "default"),
            "Tags": f"{alert.emoji},{alert.category}",
        }

        try:
            resp = requests.post(url, data=alert.message.encode("utf-8"),
                                 headers=headers, timeout=10)
            if resp.status_code == 200:
                logging.info(f"📤 Alert sent: {alert.title}")
                return True
            else:
                logging.warning(f"ntfy error: {resp.status_code}")
                return False
        except Exception as e:
            logging.error(f"ntfy send failed: {e}")
            return False

    def _flush_retries(self):
        """Attempt to resend queued alerts."""
        if not self._retry_queue:
            return

        remaining = deque(maxlen=self.RETRY_QUEUE_SIZE)
        while self._retry_queue:
            alert, attempt = self._retry_queue.popleft()
            if self._do_send(alert):
                logging.info(f"📤 Retry succeeded: {alert.title} (attempt {attempt})")
            elif attempt < self.MAX_RETRIES:
                remaining.append((alert, attempt + 1))
            else:
                logging.error(f"📤 Retry exhausted, dropping: {alert.title}")
        self._retry_queue = remaining

    def send_status(self, m: SystemMetrics):
        """Send a periodic status summary."""
        lines = [
            f"CPU: {m.cpu_percent}%{f' | {m.cpu_temp}°C' if m.cpu_temp else ''}",
            f"MEM: {m.memory_percent}% ({m.memory_used_gb}GB)",
            f"DISK: {m.disk_percent}% (잔여 {m.disk_free_gb}GB)",
        ]
        if m.battery_percent is not None:
            plug = "🔌" if m.battery_plugged else "🔋"
            lines.append(f"BAT: {plug} {m.battery_percent}%"
                        f"{f' ({m.battery_minutes_left}분)' if m.battery_minutes_left else ''}")
        if m.fan_speed_rpm:
            lines.append(f"FAN: {m.fan_speed_rpm} RPM")
        if m.ai_processes:
            lines.append(f"AI: {len(m.ai_processes)}개 프로세스, CPU {m.ai_cpu_total:.0f}%")
            top = m.ai_processes[0]
            lines.append(f"  Top: {top['name']} ({top['cpu']}%)")

        message = "\n".join(lines)
        alert = Alert(
            level="info", category="status",
            title="📊 Sentinel 상태 보고",
            message=message,
            priority=1
        )
        self.send(alert)


# ─────────────────────────────────────────────
# Main Daemon
# ─────────────────────────────────────────────

class Sentinel:
    """Main monitoring daemon."""

    def __init__(self, config_path: str = None):
        # Prevent duplicate instances via PID file lock
        self._pid_file = None
        self._data_dir = resolve_data_dir()
        self._acquire_lock()

        resolved = resolve_config_path(config_path)
        self.config = load_config(resolved)

        # Setup logging with rotation (max 5MB x 3 files = 15MB)
        log_dir = self._data_dir
        log_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                RotatingFileHandler(
                    log_dir / "sentinel.log",
                    maxBytes=5 * 1024 * 1024,
                    backupCount=3,
                ),
                logging.StreamHandler()
            ]
        )

        self.collector = MacOSCollector()
        self.engine = AlertEngine(self.config)
        self.notifier = NtfyNotifier(self.config)

        self.interval = self.config.get("check_interval_seconds", 30)
        self.status_interval = self.config.get("status_interval_minutes", 60)
        self._last_status = datetime.min
        self._running = True

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

    def _acquire_lock(self):
        """Prevent duplicate daemon instances using a file lock."""
        lock_file = self._data_dir / "sentinel.lock"
        self._pid_file = open(lock_file, "w")
        try:
            fcntl.flock(self._pid_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._pid_file.write(str(os.getpid()))
            self._pid_file.flush()
        except OSError:
            print(f"ERROR: Sentinel is already running. Lock file: {lock_file}")
            sys.exit(1)

    def _shutdown(self, signum, frame):
        logging.info("🛑 Sentinel shutting down...")
        self._running = False
        if self._pid_file:
            fcntl.flock(self._pid_file, fcntl.LOCK_UN)
            self._pid_file.close()

    def run(self):
        logging.info(f"🚀 Sentinel started — topic: {self.config.get('ntfy_topic')}")
        logging.info(f"   Check interval: {self.interval}s")
        logging.info(f"   Status report every: {self.status_interval}min")

        self.notifier.send(Alert(
            level="info", category="startup",
            title="🚀 Sentinel 시작됨",
            message=f"모니터링 간격: {self.interval}초\n"
                   f"상태 리포트: {self.status_interval}분마다",
            priority=2
        ))

        while self._running:
            try:
                metrics = self.collector.collect()

                logging.info(
                    f"CPU:{metrics.cpu_percent}% "
                    f"{'T:' + str(metrics.cpu_temp) + '°C ' if metrics.cpu_temp else ''}"
                    f"MEM:{metrics.memory_percent}% "
                    f"DISK:{metrics.disk_percent}% "
                    f"BAT:{'🔌' if metrics.battery_plugged else '🔋'}{metrics.battery_percent}% "
                    f"AI:{len(metrics.ai_processes)}procs"
                )

                alerts = self.engine.evaluate(metrics)
                for alert in alerts:
                    logging.warning(f"🚨 {alert.level}: {alert.title}")
                    self.notifier.send(alert)

                now = datetime.now()
                if (now - self._last_status).total_seconds() > self.status_interval * 60:
                    self.notifier.send_status(metrics)
                    self._last_status = now

            except Exception as e:
                logging.error(f"Monitor error: {e}", exc_info=True)

            time.sleep(self.interval)

        logging.info("Sentinel stopped.")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    import argparse
    from sentinel_mac import __version__

    parser = argparse.ArgumentParser(description="Sentinel — AI Session Guardian")
    parser.add_argument("--config", "-c", default=None, help="Config file path")
    parser.add_argument("--once", action="store_true", help="Run once and print metrics")
    parser.add_argument("--test-notify", action="store_true", help="Send test notification")
    parser.add_argument("--version", "-v", action="version", version=f"sentinel-mac {__version__}")
    parser.add_argument("--init-config", action="store_true",
                        help="Generate config.yaml in ~/.config/sentinel/")
    args = parser.parse_args()

    if args.init_config:
        config_dir = Path.home() / ".config" / "sentinel"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.yaml"
        if config_file.exists():
            print(f"Config already exists: {config_file}")
        else:
            import secrets
            topic = f"sentinel-{secrets.token_hex(4)}"
            config_content = f"""# Sentinel — Configuration
# Generated by: sentinel --init-config

ntfy_topic: "{topic}"
ntfy_server: "https://ntfy.sh"
notifications_enabled: true

check_interval_seconds: 30
status_interval_minutes: 60
cooldown_minutes: 10

thresholds:
  battery_warning: 20
  battery_critical: 10
  battery_drain_rate: 10
  temp_warning: 85
  temp_critical: 95
  memory_critical: 90
  disk_critical: 90
  network_spike_mb: 100
  session_hours_warning: 3
"""
            config_file.write_text(config_content)
            print(f"Config created: {config_file}")
            print(f"Your ntfy topic: {topic}")
            print(f"Subscribe to this topic in the ntfy app on your phone.")
        return

    if args.once:
        collector = MacOSCollector()
        m = collector.collect()
        print(f"\n{'='*50}")
        print(f"  Sentinel — System Snapshot")
        print(f"  {m.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}")
        print(f"  CPU:     {m.cpu_percent}%{f'  |  {m.cpu_temp}°C' if m.cpu_temp else ''}")
        print(f"  Thermal: {m.thermal_pressure}")
        print(f"  Memory:  {m.memory_percent}% ({m.memory_used_gb}GB)")
        if m.battery_percent is not None:
            plug = "충전중 🔌" if m.battery_plugged else "배터리 🔋"
            print(f"  Battery: {m.battery_percent}% ({plug})")
            if m.battery_minutes_left:
                print(f"           예상 {m.battery_minutes_left}분 남음")
            if m.battery_cycle_count:
                print(f"           사이클: {m.battery_cycle_count}회")
        print(f"  Disk:    {m.disk_percent}% (잔여 {m.disk_free_gb}GB)")
        if m.fan_speed_rpm:
            print(f"  Fan:     {m.fan_speed_rpm} RPM")
        print(f"  Network: ↑{m.net_sent_mb}MB ↓{m.net_recv_mb}MB")
        if m.ai_processes:
            print(f"\n  AI Processes ({len(m.ai_processes)}):")
            for p in m.ai_processes[:5]:
                print(f"    {p['name']:20s} CPU:{p['cpu']:5.1f}%  MEM:{p['mem_mb']:.0f}MB")
        else:
            print(f"\n  AI Processes: none detected")
        print(f"{'='*50}\n")
        return

    if args.test_notify:
        resolved = resolve_config_path(args.config)
        config = load_config(resolved)
        notifier = NtfyNotifier(config)
        notifier.send(Alert(
            level="info", category="test",
            title="🧪 Sentinel 테스트",
            message="알림이 정상적으로 도착했습니다! ✅\n"
                   f"Topic: {config.get('ntfy_topic')}",
            priority=3
        ))
        print("✅ Test notification sent!")
        return

    sentinel = Sentinel(config_path=args.config)
    sentinel.run()


if __name__ == "__main__":
    main()
