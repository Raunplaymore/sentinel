<p align="center">
  <h1 align="center">Sentinel</h1>
  <p align="center">
    <strong>AI Session Guardian for macOS</strong>
  </p>
  <p align="center">
    A lightweight monitoring daemon that watches your MacBook's battery, thermal, memory, disk,<br/>
    and network while AI agents run — and sends smart alerts to your phone.
  </p>
  <p align="center">
    <a href="https://pypi.org/project/sentinel-mac/"><img src="https://img.shields.io/pypi/v/sentinel-mac" alt="PyPI"></a>
    <img src="https://img.shields.io/badge/platform-macOS-blue" alt="macOS">
    <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/notifications-ntfy.sh-yellow" alt="ntfy.sh">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT License">
    <br/>
    <a href="https://buymeacoffee.com/pmpt_cafe"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-orange?logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
  </p>
</p>

---

## Why Sentinel?

Running AI agents like Claude, GPT, or Ollama for hours and stepping away? We've all been there.

Here's what you come back to:

- Battery hit 0% — session gone
- CPU throttled from overheating — work stalled
- Out of memory — process killed
- Stuck in an infinite loop — burning power for hours

**Sentinel** solves this. It checks system health every 30 seconds and sends instant alerts to your phone when something goes wrong.

## Quick Start

### Option A: pip install (PyPI)

```bash
pip install sentinel-mac
sentinel --init-config     # Generate config + auto-assign ntfy topic
sentinel --once            # One-shot system check
sentinel                   # Start daemon
```

### Option B: git clone (with macOS auto-start)

```bash
git clone https://github.com/raunplaymore/sentinel.git
cd sentinel
bash install.sh            # venv + dependencies + launchd registration (auto-start on login)
```

**Phone Setup**

1. Install the [ntfy app](https://ntfy.sh) (iOS / Android)
2. Subscribe to the topic printed during setup

That's it. Alerts will arrive automatically.

## What It Monitors

| Category | What | Alert Condition |
|:--------:|------|----------------|
| **Battery** | Level, charging state, drain rate (%/h) | Below 20%, rapid drain detected |
| **Thermal** | CPU temperature, thermal throttling | Above 85°C, throttling active |
| **Memory** | Usage, AI process consumption | Above 90% |
| **Disk** | Disk usage, remaining space | Above 90% |
| **AI Session** | Process detection, runtime duration | 3h+, suspected infinite loop |
| **Network** | Transfer volume tracking | Over 100MB per interval |
| **Night Watch** | Late-night session + battery drain | 12AM–6AM, unplugged with active session |

## Smart Alerts

Not just simple thresholds — Sentinel combines **multiple signals** for context-aware alerts:

```
🔴 Critical     Battery 10% + charger disconnected + AI session active
                 → Urgent alert (sound + vibration)

🟠 Warning      AI process high CPU but no network I/O
                 → Suspected infinite loop

🟡 Night Watch  3 AM + AI session + battery draining
                 → Unattended overnight session detected

📊 Status       Automatic hourly status report
                 → CPU, memory, battery, disk summary
```

Alerts use per-category cooldowns to prevent spam while ensuring timely delivery. Critical alerts have a 1/3 shorter cooldown for faster repeat notifications in emergencies.

## AI Process Detection

Sentinel identifies AI processes using a 3-tier strategy:

| Tier | Method | Example |
|:----:|--------|---------|
| **1** | Known AI process names | `ollama`, `llamaserver`, `mlx_lm` |
| **2** | Generic process + command-line keywords | `python3` + `transformers` |
| **3** | Command-line keywords only | `*` + `langchain`, `torch` |

This prevents false positives from generic `node` or `python3` processes.

## Commands

```bash
# One-shot system check
sentinel --once

# Example output:
# ==================================================
#   Sentinel — System Snapshot
#   2025-01-15 14:32:10
# ==================================================
#   CPU:     23.4%
#   Thermal: nominal
#   Memory:  67.2% (10.8GB)
#   Battery: 85.3% (charging 🔌)
#   Disk:    45.2% (234.5GB remaining)
#   Network: ↑0.12MB ↓1.45MB
#
#   AI Processes (2):
#     ollama               CPU: 45.2%  MEM:3200MB
#     python3              CPU: 12.1%  MEM: 890MB
# ==================================================

# Test notification (sends test alert to your phone)
sentinel --test-notify

# Check version
sentinel --version

# View live logs
tail -f logs/sentinel.log

# Service management
launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist  # Stop
launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist    # Start
```

## Configuration

All settings can be adjusted in `config.yaml`:

```yaml
# Monitoring
check_interval_seconds: 30    # Check interval (seconds)
status_interval_minutes: 60   # Status report frequency (minutes)
cooldown_minutes: 10          # Duplicate alert suppression (minutes)

# Thresholds
thresholds:
  battery_warning: 20         # Battery warning (%)
  battery_critical: 10        # Battery critical (%)
  battery_drain_rate: 10      # Rapid drain threshold (%/hour)
  temp_warning: 85            # CPU temp warning (°C)
  temp_critical: 95           # CPU temp critical (°C)
  memory_critical: 90         # Memory warning (%)
  disk_critical: 90           # Disk warning (%)
  network_spike_mb: 100       # Network spike threshold (MB/interval)
  session_hours_warning: 3    # Long session warning (hours)
```

Falls back to built-in defaults if the config file is missing or corrupted.

## Optional: CPU Temperature

Sentinel uses macOS thermal pressure by default. For exact CPU temperature readings:

```bash
brew install osx-cpu-temp
```

Sentinel will auto-detect it once installed.

## Architecture

```
sentinel/
├── pyproject.toml          # PyPI package definition
├── LICENSE
├── README.md
├── sentinel_mac/           # Python package
│   ├── __init__.py         # Version info
│   ├── __main__.py         # python -m sentinel_mac
│   └── core.py             # All core logic
├── sentinel.py             # install.sh compatibility wrapper
├── config.yaml             # User config template
├── install.sh              # One-command install + launchd setup
└── uninstall.sh            # Clean removal
```

**Internal Flow:**

```
MacOSCollector          Collect system metrics (psutil + macOS native)
       ↓
  AlertEngine           Evaluate compound conditions + manage cooldowns
       ↓
  NtfyNotifier          Deliver alerts + retry queue on failure
       ↓
    Sentinel             Main loop + signal handling + PID lock
```

## Reliability

- **Log Rotation** — 5MB x 3 files, won't eat your disk
- **Single Instance Lock** — File lock prevents duplicate daemons
- **Alert Retry** — Up to 3 retries on network failure
- **Config Fallback** — Auto-switches to defaults on config errors
- **Graceful Shutdown** — Clean lock release on SIGTERM/SIGINT
- **Auto Restart** — launchd KeepAlive restarts on crash

## Requirements

- macOS 10.15+ (Catalina or later)
- Python 3.8+
- Internet connection (for ntfy.sh alerts)

Dependencies are installed automatically by `install.sh`:
- `psutil` — System metrics
- `pyyaml` — Config parsing
- `requests` — HTTP alert delivery

## Uninstall

```bash
bash uninstall.sh
```

Stops the service, removes the virtual environment and logs. Source and config files are preserved.

Full removal: `rm -rf sentinel/`

## Roadmap

- [ ] Web dashboard (local Flask + real-time charts)
- [ ] Session end report (duration, consumption, peak temperature summary)
- [ ] Discord / Telegram bot (two-way remote control)
- [ ] API cost tracking (proxy-based token counting)
- [ ] Multi-device aggregation

## Support

If Sentinel saved your session, consider buying me a coffee!

<a href="https://buymeacoffee.com/pmpt_cafe">
  <img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=pmpt_cafe&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" />
</a>

## License

MIT
