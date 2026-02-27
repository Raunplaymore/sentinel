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
echo -e "${CYAN}║    🛡️  Sentinel — AI Session Guardian  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Check Python ──
echo -e "${YELLOW}[1/5]${NC} Python 확인..."
if command -v python3 &>/dev/null; then
    PY=$(python3 --version)
    echo -e "  ✅ $PY"
else
    echo -e "  ${RED}❌ Python 3 필요. brew install python3${NC}"
    exit 1
fi

# ── Step 2: Create venv & install deps ──
echo -e "${YELLOW}[2/5]${NC} 가상환경 설정..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo -e "  ✅ venv 생성됨"
else
    echo -e "  ✅ 기존 venv 사용"
fi

source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet "$SCRIPT_DIR"
echo -e "  ✅ 패키지 설치 완료"

# ── Step 3: Generate unique topic ──
echo -e "${YELLOW}[3/5]${NC} ntfy.sh 토픽 설정..."
EXISTING_TOPIC=$(grep "ntfy_topic:" "$SCRIPT_DIR/config.yaml" | awk '{print $2}' | tr -d '"')

if [ "$EXISTING_TOPIC" = "sentinel-CHANGE-ME" ] || [ -z "$EXISTING_TOPIC" ]; then
    RANDOM_ID=$(python3 -c "import secrets; print(secrets.token_hex(4))")
    TOPIC="sentinel-${RANDOM_ID}"
    sed -i.bak "s/ntfy_topic:.*/ntfy_topic: \"${TOPIC}\"/" "$SCRIPT_DIR/config.yaml"
    rm -f "$SCRIPT_DIR/config.yaml.bak"
    echo -e "  ✅ 토픽 생성: ${GREEN}${TOPIC}${NC}"
else
    TOPIC="$EXISTING_TOPIC"
    echo -e "  ✅ 기존 토픽 사용: ${GREEN}${TOPIC}${NC}"
fi

# ── Step 4: Setup launchd ──
echo -e "${YELLOW}[4/5]${NC} 자동 시작 설정..."
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
echo -e "  ✅ LaunchAgent 설정됨"

# ── Step 5: Test & Start ──
echo -e "${YELLOW}[5/5]${NC} 테스트 & 시작..."
mkdir -p "$SCRIPT_DIR/logs"

# Quick test
"$VENV_DIR/bin/sentinel" --config "$SCRIPT_DIR/config.yaml" --once

# Send test notification
"$VENV_DIR/bin/sentinel" --config "$SCRIPT_DIR/config.yaml" --test-notify

# Start service
launchctl load "$PLIST_PATH"
echo -e "  ✅ Sentinel 서비스 시작됨"

# ── Done! ──
echo ""
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ 설치 완료!${NC}"
echo -e "${GREEN}══════════════════════════════════════${NC}"
echo ""
echo -e "  📱 ${CYAN}핸드폰 설정 (1분 소요):${NC}"
echo ""
echo -e "  1. ntfy 앱 설치"
echo -e "     iOS:     https://apps.apple.com/app/ntfy/id1625396347"
echo -e "     Android: https://play.google.com/store/apps/details?id=io.heckel.ntfy"
echo ""
echo -e "  2. 앱에서 구독 추가 → 토픽 입력:"
echo -e "     ${GREEN}${TOPIC}${NC}"
echo ""
echo -e "  끝! 이제 알림이 자동으로 옵니다 🎉"
echo ""
echo -e "  ${YELLOW}유용한 명령어:${NC}"
echo -e "  상태 확인:   $VENV_DIR/bin/sentinel --config $SCRIPT_DIR/config.yaml --once"
echo -e "  알림 테스트:  $VENV_DIR/bin/sentinel --config $SCRIPT_DIR/config.yaml --test-notify"
echo -e "  로그 보기:   tail -f $SCRIPT_DIR/logs/sentinel.log"
echo -e "  서비스 중지:  launchctl unload $PLIST_PATH"
echo -e "  서비스 시작:  launchctl load $PLIST_PATH"
echo -e "  완전 삭제:   bash $SCRIPT_DIR/uninstall.sh"
echo ""
