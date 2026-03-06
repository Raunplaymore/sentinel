# AI Security Layer — Module Spec

## Architecture Overview

```
sentinel_mac/
├── core.py                  # [기존] 시스템 레이어 — 메인 데몬, AlertEngine, NtfyNotifier
├── collectors/
│   ├── __init__.py
│   ├── system.py            # [기존 MacOSCollector 이동] 시스템 메트릭 수집
│   ├── fs_watcher.py        # [신규] FSEvents 파일 접근 감시
│   ├── net_tracker.py       # [신규] 프로세스별 네트워크 연결 추적
│   └── agent_log_parser.py  # [신규] Claude Code / Cursor 로그 파싱
├── engine.py                # [기존 AlertEngine 이동 + 확장] 복합 조건 평가
├── models.py                # [신규] 공통 데이터 모델
└── notifier.py              # [기존 NtfyNotifier 이동]
```

핵심 원칙: 각 collector는 독립적으로 동작하며, 동일한 이벤트 인터페이스로 AlertEngine에 데이터를 전달한다.

---

## 1. 공통 이벤트 모델

```python
@dataclass
class SecurityEvent:
    timestamp: datetime
    source: str            # "fs_watcher" | "net_tracker" | "agent_log"
    actor_pid: int         # 이벤트를 발생시킨 프로세스 PID
    actor_name: str        # 프로세스 이름 (e.g., "claude", "node")
    event_type: str        # "file_access" | "file_modify" | "file_delete"
                           # "net_connect" | "net_data_transfer"
                           # "agent_command" | "agent_tool_use"
    target: str            # 파일 경로 또는 호스트:포트
    detail: dict           # 소스별 추가 정보
    risk_score: float = 0  # 0.0 ~ 1.0, engine이 채움
```

AlertEngine은 기존 SystemMetrics + SecurityEvent 스트림을 모두 받아서 복합 판단한다.

---

## 2. FSEvents 파일 접근 감시 (fs_watcher.py) — Priority 1

### 목적
AI 에이전트가 접근/수정/삭제하는 파일을 실시간 캡처.

### 구현 방식
- macOS FSEvents API 사용 (Python: `fsevents` 라이브러리 또는 `watchdog`)
- `watchdog`이 더 안정적이고 유지보수 활발 → watchdog 채택

### 감시 대상
```yaml
watch_paths:
  - "~/Projects"           # 사용자 프로젝트 디렉토리
  - "~/.ssh"               # SSH 키
  - "~/.env*"              # 환경변수 파일들
  - "~/.config"            # 설정 파일들
  - "~/.zshrc"             # 셸 설정
  - "~/.gitconfig"         # Git 설정

# 무시 패턴
ignore_patterns:
  - "*.pyc"
  - "__pycache__"
  - "node_modules"
  - ".git/objects"
```

### 알림 규칙
| 조건 | 레벨 | 예시 |
|------|------|------|
| AI 프로세스가 ~/.ssh/* 접근 | critical | "Claude Code가 SSH 키 읽음" |
| AI 프로세스가 .env 파일 접근 | critical | "Cursor가 .env 파일 수정" |
| 프로젝트 외부 파일 수정 | warning | "AI가 ~/.zshrc 수정" |
| 짧은 시간 대량 파일 수정 | warning | "30초간 50+ 파일 변경" |
| 바이너리/실행 파일 생성 | warning | "AI가 실행 파일 생성" |

### 핵심 로직
```python
class FSWatcher:
    def __init__(self, config, event_queue):
        self.sensitive_paths = [...]   # ~/.ssh, .env 등
        self.watch_paths = [...]       # config에서 로드
        self.event_queue = event_queue # SecurityEvent 전달용

    def start(self):
        """별도 스레드에서 watchdog Observer 실행"""

    def _on_event(self, event):
        """
        1. 이벤트 발생 파일 경로 확인
        2. 해당 파일을 접근한 프로세스 식별 (lsof 또는 /proc 대응)
        3. AI 프로세스인지 판별 (기존 MacOSCollector.AI_PROCESS_NAMES 재사용)
        4. SecurityEvent 생성 → event_queue에 push
        """
```

### 난이도: 중
- watchdog은 안정적이지만, "어떤 프로세스가 파일을 건드렸는지" 판별이 핵심 과제
- macOS의 Endpoint Security Framework가 가장 정확하나 root 권한 필요
- 현실적 접근: watchdog(파일 변경 감지) + lsof(프로세스 매핑) 조합
- 한계: lsof는 폴링이라 100% 정확하지 않음. 허용 가능한 트레이드오프.

---

## 3. 프로세스별 네트워크 연결 추적 (net_tracker.py) — Priority 2

### 목적
AI 에이전트가 어디로 데이터를 보내는지 추적. 예상 외 외부 호스트 연결 감지.

### 구현 방식
- `psutil.net_connections(kind='inet')` — 프로세스별 연결 목록
- 주기적 폴링 (check_interval과 동일 주기)

### 데이터 모델
```python
@dataclass
class ConnectionSnapshot:
    pid: int
    process_name: str
    remote_host: str      # IP 또는 hostname (reverse DNS)
    remote_port: int
    status: str           # ESTABLISHED, SYN_SENT 등
    direction: str        # outbound / inbound
```

### 알림 규칙
| 조건 | 레벨 | 예시 |
|------|------|------|
| AI 프로세스가 알려지지 않은 호스트 연결 | warning | "claude가 unknown-host.ru:443 연결" |
| 비표준 포트 사용 | warning | "AI가 port 4444 outbound 연결" |
| 새 외부 연결 급증 | info | "30초간 10+ 새 연결" |

### Allowlist (기본)
```yaml
net_allowlist:
  - "api.anthropic.com"
  - "api.openai.com"
  - "*.github.com"
  - "*.githubusercontent.com"
  - "pypi.org"
  - "registry.npmjs.org"
  - "ntfy.sh"               # sentinel 자체 알림
```

### 난이도: 하~중
- psutil.net_connections()가 대부분 해결
- reverse DNS 캐싱, allowlist 매칭만 구현하면 됨

---

## 4. AI 에이전트 로그 파싱 (agent_log_parser.py) — Priority 3

### 목적
Claude Code, Cursor 등이 남기는 로그에서 실제 행동(tool 호출, 파일 편집, 명령 실행)을 파싱.

### 대상 로그 위치
```
Claude Code:
  ~/.claude/projects/*/logs/
  ~/.claude.log (if exists)

Cursor:
  ~/Library/Application Support/Cursor/logs/
  ~/.cursor/logs/

VS Code + Continue:
  ~/Library/Application Support/Code/logs/
```

### 파싱 대상 이벤트
| 이벤트 | 소스 | 위험도 |
|--------|------|--------|
| Bash 명령 실행 | Claude Code log | 명령 내용에 따라 |
| 파일 생성/수정 | Claude Code log | 경로에 따라 |
| 외부 URL fetch | Claude Code log | URL에 따라 |
| MCP 서버 호출 | Claude Code log | 서버 종류에 따라 |
| pip/npm install | 명령 로그 | 패키지 평판에 따라 |

### 고위험 패턴 (즉시 알림)
```python
HIGH_RISK_PATTERNS = [
    r"curl\s+.*\|\s*sh",              # pipe to shell
    r"chmod\s+\+x",                    # make executable
    r"ssh\s+",                         # SSH 접속 시도
    r"scp\s+",                         # 파일 전송
    r"rm\s+-rf\s+[~/]",               # 위험한 삭제
    r"eval\s*\(",                      # dynamic eval
    r"base64\s+(-d|--decode)",         # 인코딩 우회
    r"nc\s+-l",                        # netcat listener
    r"pip\s+install\s+(?!-r)",         # 임의 패키지 설치
    r"npm\s+install\s+(?!--save-dev)", # 임의 패키지 설치
]
```

### 난이도: 중~상
- 로그 포맷이 에이전트마다 다르고, 버전별로 변할 수 있음
- Claude Code의 JSONL 로그가 가장 구조화되어 있어 먼저 지원
- tail -f 스타일 실시간 파싱 필요 (watchdog 또는 polling)

---

## 5. 통합 흐름

```
                    ┌─────────────┐
                    │  config.yaml │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌──────────────┐
    │  FSWatcher   │ │ NetTracker  │ │AgentLogParser│
    │  (watchdog)  │ │  (psutil)   │ │ (tail/parse) │
    └──────┬──────┘ └──────┬──────┘ └──────┬───────┘
           │               │               │
           ▼               ▼               ▼
        SecurityEvent   SecurityEvent   SecurityEvent
           │               │               │
           └───────────────┼───────────────┘
                           ▼
              ┌────────────────────────┐
              │   AlertEngine (확장)    │
              │                        │
              │  SystemMetrics ────┐   │
              │  SecurityEvents ───┤   │
              │                    ▼   │
              │            복합 판단    │
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │     NtfyNotifier       │
              └────────────────────────┘
```

### 스레딩 모델
- 메인 스레드: 기존 시스템 메트릭 수집 루프 (30초 간격)
- 스레드 1: FSWatcher (이벤트 드리븐, watchdog)
- 스레드 2: AgentLogParser (tail -f 스타일)
- NetTracker: 메인 루프에 통합 (폴링 기반이므로)
- SecurityEvent는 `queue.Queue`로 메인 스레드에 전달

---

## 6. Config 확장

```yaml
# 기존 시스템 레이어 설정 유지
check_interval_seconds: 30
# ...

# AI 보안 레이어 (신규)
security:
  enabled: true

  fs_watcher:
    enabled: true
    watch_paths:
      - "~/Projects"
    sensitive_paths:
      - "~/.ssh"
      - "~/.env"
      - "~/.config"
      - "~/.zshrc"
      - "~/.gitconfig"
    ignore_patterns:
      - "*.pyc"
      - "__pycache__"
      - "node_modules"
      - ".git/objects"
    bulk_threshold: 50        # N files in 30s → alert
    bulk_window_seconds: 30

  net_tracker:
    enabled: true
    allowlist:
      - "api.anthropic.com"
      - "api.openai.com"
      - "*.github.com"
      - "pypi.org"
      - "registry.npmjs.org"
      - "ntfy.sh"
    alert_on_unknown: true

  agent_logs:
    enabled: true
    parsers:
      - type: "claude_code"
        log_dir: "~/.claude"
      - type: "cursor"
        log_dir: "~/Library/Application Support/Cursor"
```

---

## 7. 구현 순서

### Step 1: 리팩터 (0.5일)
- core.py에서 MacOSCollector → collectors/system.py 분리
- AlertEngine → engine.py 분리
- NtfyNotifier → notifier.py 분리
- models.py에 SystemMetrics, Alert, SecurityEvent 통합
- 기존 테스트 통과 확인

### Step 2: FSWatcher (1일)
- watchdog 기반 파일 변경 감지
- sensitive_paths 접근 시 즉시 알림
- bulk 변경 감지
- AI 프로세스 매핑 (lsof 기반, best-effort)

### Step 3: NetTracker (0.5일)
- psutil.net_connections() 기반
- allowlist 매칭
- unknown host 알림

### Step 4: AgentLogParser — Claude Code (1일)
- Claude Code JSONL 로그 포맷 분석
- 고위험 패턴 매칭
- tail -f 스타일 실시간 파싱

### Step 5: 통합 테스트 + config 확장 (0.5일)

총 예상: ~3.5일 (순수 구현 기준)

---

## 8. Phase 2 확장성 — 팀 대시보드 연동

현재 설계가 팀 레이어로 자연스럽게 확장되려면, SecurityEvent가 **로컬 소비 + 원격 전송 모두 가능한 구조**여야 한다.

### 설계 원칙
- 모든 SecurityEvent는 JSON 직렬화 가능 (dataclass → dict → JSON)
- 로컬에서는 AlertEngine이 소비하고, 동시에 **이벤트 로그 파일**에 JSONL로 기록
- Phase 2에서는 이 JSONL을 팀 서버로 전송하는 `Uploader`만 추가하면 됨

### 이벤트 로그 (Phase 1에서 미리 구현)
```
~/.local/share/sentinel/events/
├── 2026-03-07.jsonl      # 일별 이벤트 로그
├── 2026-03-06.jsonl
└── ...
```

```jsonl
{"ts":"2026-03-07T14:32:10","source":"fs_watcher","actor":"claude","event_type":"file_modify","target":"~/.zshrc","risk_score":0.8}
{"ts":"2026-03-07T14:32:15","source":"net_tracker","actor":"node","event_type":"net_connect","target":"unknown-host.ru:443","risk_score":0.9}
```

### Phase 2 전환 시 추가되는 것
```
sentinel_mac/
├── ...기존 모듈...
└── sync/
    ├── uploader.py        # JSONL → 팀 서버 전송 (batch, 압축)
    └── auth.py            # 팀 인증 토큰 관리
```

- 개인 사용자: 이벤트는 로컬 JSONL에만 기록 (무료)
- 팀 사용자: 이벤트가 팀 서버로도 전송 → 대시보드에서 집계 (유료)
- 코드 변경 최소화: core.py의 메인 루프는 그대로, `Uploader`가 JSONL 파일을 독립적으로 읽어서 전송

### PLG 전환 포인트
1. 개인이 설치 → 로컬에서 알림 받으며 가치 체감
2. "팀원들도 이거 쓰면 좋겠다" → 팀 대시보드 가입
3. 대시보드에서 팀 전체의 AI 에이전트 활동 한눈에 → 관리자가 기업 플랜 검토
4. 감사 로그 포맷팅 (Phase 4) → 컴플라이언스 요구사항 충족

### MCP 인젝션 감지 (Phase 3 준비)
- AgentLogParser가 MCP 서버 호출을 이미 캡처하므로, Phase 3에서는 여기에 **인젝션 패턴 매칭**만 추가
- 예: MCP 응답에 숨겨진 프롬프트 인젝션 탐지, 비정상적 MCP 서버 등록 감지
- SecurityEvent 모델은 변경 없이 `event_type: "mcp_injection_suspect"` 추가만으로 확장

---

## 9. 의존성 추가

```
watchdog>=3.0    # FSEvents 파일 감시
```

psutil, requests, pyyaml은 기존 의존성 유지. 추가 의존성은 watchdog 하나뿐.
