#!/bin/bash
# ───────────────────────────────────────
# Sentinel — One-Command Installer
# ───────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PLIST_NAME="com.sentinel.agent"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Sentinel — A seatbelt for your AI   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Check Python ──
echo -e "${YELLOW}[1/6]${NC} Checking Python..."
if command -v python3 &>/dev/null; then
    PY=$(python3 --version)
    echo -e "  ✅ $PY"
else
    echo -e "  ${RED}❌ Python 3 required. Run: brew install python3${NC}"
    exit 1
fi

# ── Step 2: Create venv & install deps ──
echo -e "${YELLOW}[2/6]${NC} Setting up virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo -e "  ✅ venv created"
else
    echo -e "  ✅ Using existing venv"
fi

source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet --force-reinstall --no-deps "$SCRIPT_DIR"
pip install --quiet "$SCRIPT_DIR"
echo -e "  ✅ Dependencies installed"

# ── Step 3: Install terminal-notifier ──
echo -e "${YELLOW}[3/6]${NC} Setting up macOS notifications..."
if command -v terminal-notifier &>/dev/null; then
    echo -e "  ✅ terminal-notifier already installed"
elif command -v brew &>/dev/null; then
    brew install --quiet terminal-notifier
    echo -e "  ✅ terminal-notifier installed via Homebrew"
else
    echo -e "  ⚠️  Homebrew not found — falling back to osascript for notifications"
    echo -e "     For reliable alerts, install Homebrew then run: brew install terminal-notifier"
fi

# ── Step 4: Generate unique topic ──
echo -e "${YELLOW}[4/6]${NC} Configuring ntfy.sh topic..."
EXISTING_TOPIC=$(grep "ntfy_topic:" "$SCRIPT_DIR/config.yaml" | awk '{print $2}' | tr -d '"')

if [ "$EXISTING_TOPIC" = "sentinel-CHANGE-ME" ] || [ -z "$EXISTING_TOPIC" ]; then
    RANDOM_ID=$(python3 -c "import secrets; print(secrets.token_hex(4))")
    TOPIC="sentinel-${RANDOM_ID}"
    sed -i.bak "s/ntfy_topic:.*/ntfy_topic: \"${TOPIC}\"/" "$SCRIPT_DIR/config.yaml"
    rm -f "$SCRIPT_DIR/config.yaml.bak"
    echo -e "  ✅ Topic created: ${GREEN}${TOPIC}${NC}"
else
    TOPIC="$EXISTING_TOPIC"
    echo -e "  ✅ Using existing topic: ${GREEN}${TOPIC}${NC}"
fi

# ── Step 5: Setup launchd ──
echo -e "${YELLOW}[5/6]${NC} Registering auto-start service..."
mkdir -p "$HOME/Library/LaunchAgents"

cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV_DIR}/bin/sentinel</string>
        <string>--config</string>
        <string>${SCRIPT_DIR}/config.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${SCRIPT_DIR}/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${SCRIPT_DIR}/logs/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
</dict>
</plist>
EOF

# Unload if already running
launchctl unload "$PLIST_PATH" 2>/dev/null || true
echo -e "  ✅ LaunchAgent registered"

# ── Step 6: Test & Start ──
echo -e "${YELLOW}[6/6]${NC} Testing & starting..."
mkdir -p "$SCRIPT_DIR/logs"

# Quick test
"$VENV_DIR/bin/sentinel" --config "$SCRIPT_DIR/config.yaml" --once

# Send test notification
"$VENV_DIR/bin/sentinel" --config "$SCRIPT_DIR/config.yaml" --test-notify

# Start service
launchctl load "$PLIST_PATH"
echo -e "  ✅ Sentinel service started"

# ── Step 6: Add shell alias ──
SHELL_RC="$HOME/.zshrc"
[ -f "$HOME/.bashrc" ] && [ ! -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.bashrc"

ALIAS_LINE="alias sentinel=\"${VENV_DIR}/bin/sentinel --config ${SCRIPT_DIR}/config.yaml\""
if grep -q "alias sentinel=" "$SHELL_RC" 2>/dev/null; then
    # Update existing alias to point to current venv
    sed -i.bak "/alias sentinel=/c\\${ALIAS_LINE}" "$SHELL_RC"
    rm -f "${SHELL_RC}.bak"
    echo -e "  ✅ Alias updated in $(basename $SHELL_RC)"
else
    echo "" >> "$SHELL_RC"
    echo "# Sentinel — AI Security Guardian" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    echo -e "  ✅ Alias added to $(basename $SHELL_RC) — restart terminal or run: source $SHELL_RC"
fi

# ── Done! ──
echo ""
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Installation complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo ""
echo -e "  📱 ${CYAN}Phone setup (1 minute):${NC}"
echo ""
echo -e "  1. Install the ntfy app"
echo -e "     iOS:     https://apps.apple.com/app/ntfy/id1625396347"
echo -e "     Android: https://play.google.com/store/apps/details?id=io.heckel.ntfy"
echo ""
echo -e "  2. Subscribe to your topic:"
echo -e "     ${GREEN}${TOPIC}${NC}"
echo ""
echo -e "  Done! Alerts will arrive automatically."
echo ""
echo -e "  ${YELLOW}Useful commands (restart terminal first):${NC}"
echo -e "  sentinel --once          System snapshot"
echo -e "  sentinel --report        Today's event summary"
echo -e "  sentinel --report 7      Last 7 days summary"
echo -e "  sentinel --test-notify   Test alert to all channels"
echo -e "  sentinel --help          All options"
echo -e ""
echo -e "  ${YELLOW}Service control:${NC}"
echo -e "  launchctl unload $PLIST_PATH   Stop"
echo -e "  launchctl load $PLIST_PATH     Start"
echo -e "  bash $SCRIPT_DIR/uninstall.sh         Uninstall"
echo ""
