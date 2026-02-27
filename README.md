<p align="center">
  <h1 align="center">Sentinel</h1>
  <p align="center">
    <strong>AI Session Guardian for macOS</strong>
  </p>
  <p align="center">
    AI 에이전트가 장시간 돌아갈 때, 맥북의 배터리·발열·메모리·디스크·네트워크를 감시하고<br/>
    핸드폰으로 스마트 알림을 보내주는 경량 모니터링 데몬
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

Claude, GPT, Ollama 같은 AI 에이전트를 수시간 돌려놓고 자리를 비우는 상황, 익숙하시죠?

돌아와보면 이런 일이 벌어져 있습니다:

- 배터리 0%로 세션이 날아감
- CPU 과열로 쓰로틀링 걸려 작업이 멈춤
- 메모리 부족으로 프로세스가 kill됨
- 무한루프에 빠져 몇 시간째 전력만 소모 중

**Sentinel**은 이 문제를 해결합니다. 30초마다 시스템 상태를 체크하고, 위험 상황이 감지되면 핸드폰으로 즉시 알림을 보냅니다.

## Quick Start

### Option A: pip install (PyPI)

```bash
pip install sentinel-mac
sentinel --init-config     # config 생성 + ntfy 토픽 자동 발급
sentinel --once            # 시스템 상태 즉시 확인
sentinel                   # 데몬 시작
```

### Option B: git clone (macOS 자동 시작 포함)

```bash
git clone https://github.com/raunplaymore/sentinel.git
cd sentinel
bash install.sh            # venv + 패키지 설치 + launchd 등록 (로그인 시 자동 시작)
```

**핸드폰 설정**

1. [ntfy 앱](https://ntfy.sh) 설치 (iOS / Android)
2. 설치 시 출력된 토픽을 앱에서 구독

끝. 이제 알림이 자동으로 옵니다.

## What It Monitors

| 카테고리 | 감지 항목 | 알림 조건 |
|:--------:|----------|----------|
| **Battery** | 잔량, 충전 상태, 소모 속도 (%/h) | 20% 이하, 급속 방전 감지 |
| **Thermal** | CPU 온도, thermal throttling | 85°C 이상, 쓰로틀링 |
| **Memory** | 사용률, AI 프로세스 점유량 | 90% 이상 |
| **Disk** | 디스크 사용률, 잔여 공간 | 90% 이상 |
| **AI Session** | 프로세스 식별, 실행 시간 | 3시간+, 무한루프 의심 |
| **Network** | 전송량 추적 | 간격당 100MB 초과 |
| **Night Watch** | 새벽 방치 + 배터리 사용 | 0시~6시 미충전 세션 |

## Smart Alerts

단순 임계치가 아닌, **상황을 조합한** 알림을 보냅니다:

```
🔴 Critical     배터리 10% + 충전기 미연결 + AI 세션 활성
                 → 긴급 알림 (소리 + 진동)

🟠 Warning      AI 프로세스 CPU 높은데 네트워크 I/O 없음
                 → 무한루프 의심 알림

🟡 Night Watch  새벽 3시 + AI 세션 + 배터리 방전 중
                 → 야간 방치 감지

📊 Status       매시간 자동 상태 리포트
                 → CPU, 메모리, 배터리, 디스크 요약
```

알림은 카테고리별 쿨다운이 적용되어 스팸 없이 정확한 타이밍에 도착합니다. Critical 알림은 쿨다운이 1/3로 짧아져 긴급 상황에서 빠르게 반복됩니다.

## AI Process Detection

Sentinel은 3단계 전략으로 AI 프로세스를 식별합니다:

| Tier | 방식 | 예시 |
|:----:|------|------|
| **1** | 확실한 AI 프로세스 이름 | `ollama`, `llamaserver`, `mlx_lm` |
| **2** | 일반 프로세스 + 커맨드라인 키워드 | `python3` + `transformers` |
| **3** | 커맨드라인 키워드만 | `*` + `langchain`, `torch` |

일반적인 `node`, `python3` 프로세스가 AI로 오탐되는 것을 방지합니다.

## Commands

```bash
# 현재 상태 즉시 확인
sentinel --once

# 출력 예시:
# ==================================================
#   Sentinel — System Snapshot
#   2025-01-15 14:32:10
# ==================================================
#   CPU:     23.4%
#   Thermal: nominal
#   Memory:  67.2% (10.8GB)
#   Battery: 85.3% (충전중 🔌)
#   Disk:    45.2% (잔여 234.5GB)
#   Network: ↑0.12MB ↓1.45MB
#
#   AI Processes (2):
#     ollama               CPU: 45.2%  MEM:3200MB
#     python3              CPU: 12.1%  MEM: 890MB
# ==================================================

# 알림 테스트 (핸드폰으로 테스트 알림 발송)
sentinel --test-notify

# 버전 확인
sentinel --version

# 로그 실시간 확인
tail -f logs/sentinel.log

# 서비스 관리
launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist  # 중지
launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist    # 시작
```

## Configuration

`config.yaml` 에서 모든 설정을 조정할 수 있습니다:

```yaml
# 모니터링
check_interval_seconds: 30    # 체크 간격 (초)
status_interval_minutes: 60   # 상태 리포트 주기 (분)
cooldown_minutes: 10          # 같은 알림 반복 방지 (분)

# 임계값
thresholds:
  battery_warning: 20         # 배터리 경고 (%)
  battery_critical: 10        # 배터리 긴급 (%)
  battery_drain_rate: 10      # 급속 방전 기준 (%/시간)
  temp_warning: 85            # CPU 온도 경고 (°C)
  temp_critical: 95           # CPU 온도 긴급 (°C)
  memory_critical: 90         # 메모리 경고 (%)
  disk_critical: 90           # 디스크 경고 (%)
  network_spike_mb: 100       # 네트워크 급증 기준 (MB/간격)
  session_hours_warning: 3    # 장시간 세션 경고 (시간)
```

설정 파일이 손상되거나 없어도 내장 기본값으로 동작합니다.

## Optional: CPU Temperature

기본적으로 macOS thermal pressure 기반으로 동작하지만, 정확한 CPU 온도를 보려면:

```bash
brew install osx-cpu-temp
```

설치 후 Sentinel이 자동으로 감지합니다.

## Architecture

```
sentinel/
├── pyproject.toml          # PyPI 패키지 정의
├── LICENSE
├── README.md
├── sentinel_mac/           # Python 패키지
│   ├── __init__.py         # 버전 정보
│   ├── __main__.py         # python -m sentinel_mac
│   └── core.py             # 모든 핵심 로직
├── sentinel.py             # install.sh 호환 래퍼
├── config.yaml             # 사용자 설정 템플릿
├── install.sh              # 원커맨드 설치 + launchd 등록
└── uninstall.sh            # 클린 제거
```

**내부 구조:**

```
MacOSCollector          시스템 메트릭 수집 (psutil + macOS 네이티브)
       ↓
  AlertEngine           복합 조건 평가 + 쿨다운 관리
       ↓
  NtfyNotifier          알림 발송 + 실패 시 재시도 큐
       ↓
    Sentinel             메인 루프 + 시그널 핸들링 + PID 락
```

## Reliability

- **로그 로테이션** — 5MB x 3파일, 디스크를 잡아먹지 않음
- **중복 실행 방지** — 파일 락으로 데몬 이중 실행 차단
- **알림 재시도** — 네트워크 끊김 시 최대 3회 재전송
- **설정 폴백** — config.yaml 오류 시 기본값으로 자동 전환
- **Graceful Shutdown** — SIGTERM/SIGINT 시 락 해제 후 정상 종료
- **Auto Restart** — launchd KeepAlive로 크래시 시 자동 재시작

## Requirements

- macOS 10.15+ (Catalina 이상)
- Python 3.8+
- 인터넷 연결 (ntfy.sh 알림 발송)

의존성은 `install.sh`가 자동으로 설치합니다:
- `psutil` — 시스템 메트릭
- `pyyaml` — 설정 파싱
- `requests` — HTTP 알림 발송

## Uninstall

```bash
bash uninstall.sh
```

서비스 중지, 가상환경, 로그를 제거합니다. 소스와 설정 파일은 보존됩니다.

완전 삭제: `rm -rf sentinel/`

## Roadmap

- [ ] 웹 대시보드 (로컬 Flask + 실시간 차트)
- [ ] 세션 종료 리포트 (시간, 소모량, 최고온도 요약)
- [ ] Discord / Telegram 봇 (양방향 원격 제어)
- [ ] API 비용 추적 (프록시 기반 토큰 계산)
- [ ] 멀티 디바이스 통합

## Support

Sentinel이 유용하셨다면 커피 한 잔 사주세요!

<a href="https://buymeacoffee.com/pmpt_cafe">
  <img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=pmpt_cafe&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" />
</a>

## License

MIT
