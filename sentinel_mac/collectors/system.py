"""Sentinel — System Metrics Collector (macOS-specific)."""

import re
import shutil
import subprocess
import time
from typing import Optional

import psutil

from sentinel_mac.models import SystemMetrics


class MacOSCollector:
    """Collects system metrics using macOS native tools + psutil."""

    # Only match process names that are unambiguously AI-related
    AI_PROCESS_NAMES = {
        "ollama", "llamaserver", "mlx_lm",
        # Claude Code: npm install symlink and native binary both expose name "claude"
        "claude", "claude-code",
    }

    # Match these keywords in the full command line and executable path
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
        from datetime import datetime
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

        # Security posture
        m.firewall_enabled = self._get_firewall_enabled()
        m.gatekeeper_enabled = self._get_gatekeeper_enabled()
        m.filevault_enabled = self._get_filevault_enabled()

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
            cmd = shutil.which("osx-cpu-temp") or "/usr/local/bin/osx-cpu-temp"
            out = subprocess.run(
                [cmd], capture_output=True, text=True, timeout=3
            )
            if out.returncode == 0:
                match = re.search(r"([\d.]+)\u00b0C", out.stdout)
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

    def _get_firewall_enabled(self) -> Optional[bool]:
        """Get macOS application firewall state."""
        try:
            out = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=3
            )
            text = f"{out.stdout}\n{out.stderr}".lower()
            if "disabled" in text:
                return False
            if "enabled" in text:
                return True
        except Exception:
            pass
        return None

    def _get_gatekeeper_enabled(self) -> Optional[bool]:
        """Get Gatekeeper state from spctl."""
        try:
            out = subprocess.run(
                ["spctl", "--status"],
                capture_output=True, text=True, timeout=3
            )
            text = f"{out.stdout}\n{out.stderr}".lower()
            if "assessments disabled" in text:
                return False
            if "assessments enabled" in text:
                return True
        except Exception:
            pass
        return None

    def _get_filevault_enabled(self) -> Optional[bool]:
        """Get FileVault disk encryption state."""
        try:
            out = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True, timeout=3
            )
            text = f"{out.stdout}\n{out.stderr}".lower()
            if "filevault is off" in text:
                return False
            if "filevault is on" in text:
                return True
        except Exception:
            pass
        return None

    def _get_ai_processes(self) -> list:
        """Identify AI-related processes and their resource usage.

        Detection strategy:
        - Unambiguous: process name in AI_PROCESS_NAMES, OR executable path
                       contains an AI keyword (catches native-binary install paths
                       such as VS Code extension bundles where cmdline may be opaque).
        - Ambiguous: generic name (python, node, etc.) or any process whose cmdline
                     contains an AI keyword. Subject to a CPU floor to suppress noise.
        """
        ai_procs = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                cmdline = " ".join(info["cmdline"] or []).lower()
                exe = (info["exe"] or "").lower()

                name_match = name in self.AI_PROCESS_NAMES
                exe_match = bool(exe) and any(kw in exe for kw in self.AI_CMDLINE_KEYWORDS)
                unambiguous = name_match or exe_match

                is_ai = unambiguous
                if not is_ai and name in self.GENERIC_PROCESS_NAMES:
                    is_ai = any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS)
                if not is_ai:
                    is_ai = any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS)

                if not is_ai:
                    continue

                cpu = info["cpu_percent"] or 0
                # CPU floor suppresses noise from generic/keyword matches; unambiguous
                # AI binaries are always reported even when idle (psutil's first
                # cpu_percent sample is 0, so a floor would hide them on --once).
                if not unambiguous and cpu <= 5.0:
                    continue

                mem_mb = round((info["memory_info"].rss if info["memory_info"] else 0) / (1024**2), 1)
                ai_procs.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu": round(cpu, 1),
                    "mem_mb": mem_mb,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(ai_procs, key=lambda p: p["cpu"], reverse=True)[:10]
