"""Sentinel — Data Models."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


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
    # Security posture
    firewall_enabled: Optional[bool] = None
    gatekeeper_enabled: Optional[bool] = None
    filevault_enabled: Optional[bool] = None
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
    emoji: str = "\u26a0\ufe0f"
    priority: int = 3   # ntfy: 1=min, 3=default, 5=urgent


@dataclass
class SecurityEvent:
    """Common event model for all security collectors.

    ``event_id`` is a per-event UUID4 (string form) assigned at construction.
    It enables in-place JSONL line rewrites (see ADR 0002 §D3 — agent_download
    join populates ``detail["joined_fs_event"]`` after the original line is
    already on disk). ADR 0004 §D3 additive: existing detail keys are never
    repurposed; ``event_id`` is a new top-level field, not a detail key.
    """
    timestamp: datetime
    source: str            # "fs_watcher" | "net_tracker" | "agent_log"
    actor_pid: int         # Process PID that triggered the event
    actor_name: str        # Process name (e.g., "claude", "node")
    event_type: str        # "file_access" | "file_modify" | "file_delete"
                           # "net_connect" | "net_data_transfer"
                           # "agent_command" | "agent_tool_use" | "agent_download"
    target: str            # File path or host:port
    detail: dict = field(default_factory=dict)
    risk_score: float = 0  # 0.0 ~ 1.0, scored by engine
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
