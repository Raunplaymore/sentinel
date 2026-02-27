#!/bin/bash
# ───────────────────────────────────────
# Sentinel — Uninstaller
# ───────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST_NAME="com.sentinel.agent"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo ""
echo "🛡️  Sentinel 제거"
echo ""

# Stop service
if [ -f "$PLIST_PATH" ]; then
    launchctl unload "$PLIST_PATH" 2>/dev/null
    rm -f "$PLIST_PATH"
    echo -e "  ✅ LaunchAgent 제거됨"
else
    echo -e "  ℹ️  LaunchAgent 없음"
fi

# Remove venv
if [ -d "$SCRIPT_DIR/.venv" ]; then
    rm -rf "$SCRIPT_DIR/.venv"
    echo -e "  ✅ 가상환경 제거됨"
fi

# Remove logs
if [ -d "$SCRIPT_DIR/logs" ]; then
    rm -rf "$SCRIPT_DIR/logs"
    echo -e "  ✅ 로그 제거됨"
fi

echo ""
echo -e "${GREEN}  ✅ Sentinel 제거 완료${NC}"
echo -e "  설정 파일(config.yaml)과 소스는 보존됩니다."
echo -e "  전체 삭제: rm -rf $SCRIPT_DIR"
echo ""
