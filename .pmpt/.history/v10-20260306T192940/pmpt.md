# Sentinel

## Product Idea
AI 에이전트 시대의 macOS 보안 안전망. 시스템 리소스 모니터링 + AI 에이전트 행동 감시를 결합하여, 개발자가 자리를 비운 사이에도 안전한 컴퓨팅 환경을 유지한다.

## Additional Context
- Author: raunplaymore
- License: MIT
- Platform: macOS (Apple Silicon + Intel)
- Python: 3.8+
- PyPI: `sentinel-mac`
- Git history: 4 commits since 2026-02-27
- Recent work: v0.2.0 release (bug fixes, tests, CI/CD, English localization)

## Features

### System Layer (v0.1.0)
- [x] CPU/온도/팬 모니터링 (psutil + macOS native)
- [x] 배터리 잔량/충전 상태/소모율 감시
- [x] 메모리/디스크 사용률 추적
- [x] AI 프로세스 탐지 (Claude, GPT, Ollama, Copilot 등)
- [x] 네트워크 트래픽 스파이크 감지
- [x] 장시간 세션/야간 작업 감지
- [x] ntfy.sh 기반 스마트 폰 알림
- [x] 보안 포스처 감시 (Firewall, Gatekeeper, FileVault)

### AI Security Layer (v0.2.0~)
- [x] FSWatcher — 파일 시스템 실시간 감시 (Priority 1)
- [x] NetTracker — AI 프로세스 네트워크 연결 추적 (Priority 2)
- [x] AgentLogParser — Claude Code 세션 로그 파싱 (Priority 3)

### Completed (v7~v8)
- [x] JSONL 이벤트 로깅 (Phase 2 팀 대시보드 준비)
- [x] 통합 테스트 (end-to-end security event flow)
- [x] Multi-channel notifications (macOS native + ntfy + Slack)
- [x] Critical-only alerting (warning/info log only)

### Completed (v9~v10)
- [x] MCP 인젝션 감지 — 10개 패턴, tool_result 스캔, critical 알림
- [x] pyproject.toml v0.3.0 + watchdog 의존성 반영
- [x] README 업데이트 — MCP 인젝션, Telegram, Cursor 문서화
- [x] Cursor 로그 파서 — workspaceStorage 스캔
- [x] Telegram 알림 채널 — Bot API 통합

## Architecture Decisions

### AD-1: Layered Architecture (Option 3)
**결정**: 기존 시스템 모니터를 "System Layer"로 유지하고, "AI Security Layer"를 별도 모듈로 추가.
**대안 검토**:
- Option 1 (기존 AlertEngine에 통합): 코드 복잡도 급증, 단일 파일이 비대해짐
- Option 2 (별도 데몬): 두 프로세스 관리 부담, 설정 중복
- Option 3 (레이어드): 기존 코드 변경 최소, 독립적 테스트 가능, Phase 2 확장 용이
**근거**: 기존 46개 테스트를 한 줄도 수정하지 않고 유지하면서 새 기능 추가 가능. 각 collector가 독립적이라 하나가 죽어도 나머지에 영향 없음.

### AD-2: Modular Refactor (core.py -> 5 modules)
**결정**: 단일 `core.py`를 `models.py`, `collectors/system.py`, `engine.py`, `notifier.py`로 분리. `core.py`는 re-export hub + Sentinel daemon + CLI만 유지.
**근거**: AI Security Layer 추가 시 core.py가 1000줄 이상으로 비대해질 위험. 모듈 분리 후에도 `from sentinel_mac.core import AlertEngine` 같은 기존 import가 동작하도록 re-export 패턴 적용. 기존 테스트 100% 무변경 통과.

### AD-3: SecurityEvent 공통 데이터 모델
**결정**: 3개 collector(FSWatcher, NetTracker, AgentLogParser)가 모두 동일한 `SecurityEvent` dataclass로 이벤트를 전달.
**근거**: AlertEngine이 source별로 dispatch하되, 큐/로깅/직렬화 코드는 한 벌만 유지. Phase 2에서 JSONL로 기록 후 팀 서버 전송 시 포맷 통일됨. `detail: dict` 필드로 source별 추가 정보를 유연하게 담음.

### AD-4: watchdog (FSEvents) 선택
**결정**: 파일 시스템 감시에 `watchdog` 라이브러리 사용.
**대안 검토**:
- `pyfsevents`: macOS 전용이지만 유지보수 중단 상태
- Endpoint Security Framework: 가장 정확하지만 root 권한 + entitlement 필요
- `watchdog`: cross-platform, macOS에서 FSEvents 백엔드 사용, 활발한 유지보수
**트레이드오프**: watchdog은 "어떤 프로세스가 파일을 건드렸는지" 모름. `lsof` 기반 best-effort 프로세스 매핑으로 보완. 100% 정확하진 않지만 허용 가능한 수준.

### AD-5: queue.Queue 기반 이벤트 전달
**결정**: collector 스레드 -> 메인 스레드 간 `queue.Queue(maxsize=1000)` 사용.
**근거**: 스레드 안전, 표준 라이브러리, 외부 의존성 없음. 메인 루프에서 매 사이클마다 최대 100개씩 drain하여 알림 발송. 큐 가득 차면 이벤트 드롭(안전 밸브). 메인 루프가 블로킹되어도 collector는 독립 동작.

### AD-6: NetTracker — 폴링 방식
**결정**: NetTracker는 별도 스레드 없이 메인 루프에서 `poll()` 호출.
**근거**: `psutil.net_connections()`는 스냅샷 API라 이벤트 드리븐이 불가능. 30초 간격 폴링으로 충분. 스레드 하나 줄여서 복잡도 감소. 중복 연결은 (pid, ip, port) 튜플 + 5분 TTL로 deduplicate.

### AD-7: AgentLogParser — tail-f 스타일 파싱
**결정**: Claude Code JSONL 로그를 3초 간격으로 polling하며 새 줄만 읽음.
**대안 검토**:
- watchdog으로 로그 파일 감시: 이벤트 폭풍 위험 (AI가 빠르게 쓰므로)
- `inotify`/`kqueue` 직접: 플랫폼 종속 코드 증가
- polling: 단순하고 안정적, 3초 지연은 보안 모니터링에 충분
**핵심 설계**: 첫 스캔 시 기존 내용은 건너뛰고 파일 끝 위치만 기록. 이후 스캔에서 새로 추가된 줄만 파싱. 파일 truncation(크기 줄어듦) 감지 시 처음부터 다시 읽음.
**사용자 요구사항**: 로그 디렉토리가 존재하지 않으면 명시적 WARNING 로그 출력 후 시작하지 않음 (silent fail 방지).

### AD-8: High-Risk Pattern 정규식 컴파일
**결정**: 14개 위험 패턴을 모듈 로드 시 `re.compile()`로 사전 컴파일.
**근거**: 매 로그 라인마다 14개 패턴을 매칭하므로 성능이 중요. 컴파일된 패턴은 약 10x 빠름. `pip install -r requirements.txt` 같은 안전한 패턴을 false positive 없이 제외하기 위해 negative lookahead 사용.

### AD-9: 알림 쿨다운 전략
**결정**: 카테고리별 쿨다운 (기본 10분). critical 알림은 1/3 짧은 쿨다운.
**근거**: AI 에이전트가 같은 작업을 반복하면 동일 알림이 폭주. 카테고리 단위로 중복 억제하되, critical은 더 자주 알려야 하므로 짧은 쿨다운 적용. NetTracker는 추가로 (pid, ip, port) 튜플 기반 5분 TTL deduplicate.

### AD-10: Re-export 패턴으로 하위 호환
**결정**: `core.py`에서 분리된 모든 클래스를 `from sentinel_mac.core import X`로 계속 사용 가능하게 re-export.
**근거**: 기존 테스트와 `sentinel.py` 엔트리포인트가 `from sentinel_mac.core import MacOSCollector` 등을 사용 중. import 경로를 강제로 바꾸면 불필요한 churn 발생. re-export로 기존 코드 무변경 유지.

## Project Structure
```
sentinel_mac/
├── core.py                  # Sentinel daemon, config, CLI, re-exports
├── models.py                # SystemMetrics, Alert, SecurityEvent
├── engine.py                # AlertEngine (system + security event evaluation)
├── notifier.py              # NotificationManager + channels (macOS, ntfy, Slack)
├── event_logger.py          # EventLogger (daily JSONL event logging)
└── collectors/
    ├── system.py            # MacOSCollector (CPU, battery, disk, etc.)
    ├── fs_watcher.py        # FSWatcher (watchdog + lsof)
    ├── net_tracker.py       # NetTracker (psutil.net_connections + DNS)
    └── agent_log_parser.py  # AgentLogParser (Claude Code JSONL tail-f)

tests/
├── test_alerts.py           # AlertEngine system metrics tests (26)
├── test_config.py           # Config loading/validation tests (11)
├── test_notifier.py         # Notification system tests (23)
├── test_fs_watcher.py       # FSWatcher + security event alert tests (27)
├── test_net_tracker.py      # NetTracker + network event alert tests (23)
├── test_agent_log_parser.py # AgentLogParser + agent event alert tests (31)
└── test_integration.py      # EventLogger + end-to-end integration tests (11)

Total: 155 tests passing
```

## Threading Model
```
Main Thread (30s loop):
  MacOSCollector.collect() -> AlertEngine.evaluate() -> NtfyNotifier
  NetTracker.poll() -> SecurityEvent -> queue
  _process_security_events() <- drain queue -> AlertEngine -> NtfyNotifier

Thread 1 (FSWatcher):
  watchdog Observer -> _handle_fs_event() -> SecurityEvent -> queue

Thread 2 (AgentLogParser):
  3s polling -> _scan_claude_code_logs() -> parse_line() -> SecurityEvent -> queue
```

## Dependencies
- `psutil>=5.9` — system metrics, network connections, process info
- `pyyaml>=6.0` — config parsing
- `requests>=2.28` — ntfy.sh HTTP push
- `watchdog>=3.0` — macOS FSEvents file monitoring
- `pytest>=7.0` (dev) — test framework

## Progress
- [x] v0.1.0 — Initial release (system monitoring + ntfy alerts)
- [x] v0.2.0 — Bug fixes, tests, CI/CD, English localization
- [x] Security Posture Watch (Firewall, Gatekeeper, FileVault)
- [x] AI Security Layer spec design
- [x] Modular refactor (core.py -> 5 modules)
- [x] FSWatcher implementation + 27 tests
- [x] NetTracker implementation + 23 tests
- [x] AgentLogParser implementation + 31 tests
- [x] JSONL event logging (Phase 2 prep)
- [x] Integration test (end-to-end)
- [x] Multi-channel notifications (macOS native + ntfy + Slack)
- [x] Critical-only alerting (warning/info log only)
- [x] MCP 인젝션 감지 — 10개 패턴 + critical 알림
- [x] pyproject.toml v0.3.0 + watchdog 의존성
- [x] README 업데이트 — MCP, Telegram, Cursor 문서화
- [x] Cursor 로그 파서 + Telegram 알림 채널

## Snapshot Log

### v1 - Initial Setup
- Project initialized with pmpt

### v2 - Security Posture Watch
- Added security posture monitoring for Firewall, Gatekeeper, and FileVault.
- Added `security_posture` alert generation and surfaced security status in periodic reports and `--once` output.
- Fixed two baseline regressions (`load_config` non-mapping YAML handling, cooldown timestamp behavior).
- Test result: `46 passed`.

### v3 - AI Security Layer Foundation
- Decided on Option 3: layered architecture (system layer + AI security layer).
- Created AI Security Layer spec (`ai-security-layer-spec.md`).
- Refactored `core.py` into modular structure with re-export backward compatibility.
- Added `SecurityEvent` data model for upcoming security collectors.
- Test result: `46 passed` (zero regression).

### v4 - FSWatcher Implementation
- Implemented `collectors/fs_watcher.py`: watchdog Observer + lsof-based process attribution.
- Detects sensitive path access (~/.ssh, .env), executable file creation, AI process file activity, bulk changes.
- Added `evaluate_security_event()` to AlertEngine for SecurityEvent -> Alert conversion with cooldown.
- Integrated FSWatcher into Sentinel daemon via shared `queue.Queue` + drain loop.
- Test result: `73 passed` (+27 new).

### v5 - NetTracker Implementation
- Implemented `collectors/net_tracker.py`: psutil.net_connections polling, reverse DNS caching, fnmatch allowlist.
- Tracks AI process outbound connections. Flags unknown hosts (warning), unknown + non-standard port (critical).
- Duplicate connection deduplication with 5-min TTL.
- Test result: `96 passed` (+23 new).

### v6 - AgentLogParser Implementation
- Implemented `collectors/agent_log_parser.py`: Claude Code JSONL session log parser with tail-f style reading.
- 14 compiled HIGH_RISK_PATTERNS: curl|sh, wget|bash, chmod+x, ssh, rm -rf, base64 decode, netcat, pip/npm install, etc.
- Parses `tool_use` content blocks: Bash (command risk check), Write (sensitive path detection), WebFetch (URL fetch logging).
- Background thread with 3s polling, skips existing content on first scan, tracks file positions per session.
- Explicit WARNING log when configured log directories are not found (user requirement).
- Test result: `127 passed` (+31 new).

### v7 - JSONL Event Logging + Integration Tests
- Implemented `event_logger.py`: append-only JSONL event logger with daily file rotation.
- All SecurityEvents are now logged to `<data_dir>/events/YYYY-MM-DD.jsonl` before alert evaluation.
- Phase 2 팀 대시보드 준비: 로컬 JSONL에 모든 이벤트 기록, 나중에 `Uploader`만 추가하면 서버 전송 가능.
- Integrated EventLogger into Sentinel daemon (`_process_security_events` drain loop + shutdown close).
- 11 new tests: EventLogger unit tests (6) + end-to-end integration tests (5).
  - Integration tests verify: FSWatcher -> critical alert + JSONL, NetTracker -> warning + JSONL, AgentLogParser -> critical + JSONL, queue drain flow, safe events logged without alerts.
- Test result: `138 passed` (+11 new).

### AD-11: JSONL Event Logging (Phase 2 준비)
**결정**: 모든 SecurityEvent를 알림 발송과 동시에 일별 JSONL 파일에 기록.
**근거**: Phase 2 팀 대시보드에서 이벤트 히스토리가 필요. 지금부터 로컬에 기록해두면 (1) 개인 사용자도 감사 이력 확인 가능, (2) Phase 2에서 `Uploader` 모듈만 추가하면 됨. 알림이 발생하지 않는 이벤트도 기록하여 완전한 감사 로그 확보. daily rotation으로 파일 관리 용이.

### v8 - Multi-channel Notification + Critical-only Alerting
- Redesigned notification system: single `NtfyNotifier` -> multi-channel `NotificationManager`.
- 3 notification channels: macOS native (osascript, 기본값), ntfy.sh (선택), Slack webhook (선택).
- "값이 있으면 활성화" 패턴: `ntfy_topic`에 값 넣으면 ntfy 활성화, `slack_webhook`에 URL 넣으면 Slack 활성화. 별도 on/off 불필요.
- **Critical-only 알림 원칙**: critical 알림만 채널로 발송, warning/info는 로그에만 기록. "감시는 전부, 알림은 최소."
- macOS native notification: `osascript display notification` 사용, critical은 사운드 포함.
- Config 구조 변경: `ntfy_topic`/`notifications_enabled` -> `notifications:` 블록. 기존 top-level `ntfy_topic` 하위 호환 유지.
- `--init-config` 생성 config 업데이트, `--test-notify`는 NotificationManager 사용.
- 23 new notifier tests (NtfyNotifier 5, MacOSNotifier 4, SlackNotifier 2, NotificationManager 12).
- Test result: `155 passed` (+17 net new, 6 old replaced).

### AD-12: Multi-channel Notification + Critical-only Delivery
**결정**: macOS 네이티브 알림을 기본 채널로, critical 이벤트만 알림 발송.
**대안 검토**:
- ntfy.sh만 유지: 초기 설정이 필요해서 "설치하면 바로 동작" 원칙에 위배
- 모든 레벨 알림: 오탐이 많으면 유저가 Sentinel을 끔. 보안 도구의 가장 큰 적은 알림 피로
**핵심 원칙**: "감시는 전부, 알림은 최소." Warning/Info는 JSONL 감사 로그에 기록되므로 데이터 손실 없음. Critical만 즉시 알림으로 유저 주의를 끔.
**"값이 있으면 활성화" 패턴**: `slack_webhook: "https://..."` -> Slack 자동 활성화. 유저가 별도 `enabled: true`를 설정할 필요 없음. 비어있으면 꺼짐.
**하위 호환**: 기존 top-level `ntfy_topic` 설정도 계속 동작. `notifications.ntfy_topic`이 명시되어 있으면 우선.

### AD-13: macOS 전용 전략 (Linux 미지원)
**결정**: Linux 지원을 보류하고 macOS에 집중.
**대안 검토**:
- Linux 지원 추가: 코드의 90%가 이미 크로스 플랫폼이지만, system.py의 70%가 macOS 전용 (pmset, ioreg, spctl 등). LinuxCollector 구현 + 2개 플랫폼 테스트/유지 부담.
- 결론: AI 코딩 에이전트(Claude Code, Cursor)의 주 사용 환경이 macOS 데스크탑. Linux 서버는 이미 Prometheus/Grafana 등 성숙한 도구가 있음.
**근거**: macOS에서 확실한 PMF를 먼저 잡고, 유저 요청이 있으면 그때 Linux 지원 추가. 지금은 MCP 인젝션 감지 같은 차별화 기능에 리소스 집중.

---
*This document tracks project progress. Update it as you build.*
*AI instructions are in `pmpt.ai.md` -- paste that into your AI tool.*

### v9 — 2026-03-06
- Updated project plan: decided macOS-first strategy (AD-13), dropping Linux support to focus on differentiation features
- Reorganized Planned/Next sections — MCP injection detection is now top priority as Sentinel's key differentiator
- Cleaned up duplicate snapshot logs from v8 backfill
- Updated pmpt.ai.md What's Next to reflect new priorities

### v10 — 2026-03-06
- Implemented three major features: (1) MCP injection detection with 10 compiled patterns scanning tool_result responses for prompt injection (system tags, instruction overrides, role hijacking, concealment, HTML injection, urgency manipulation, token boundaries, fake system prompts) — triggers critical alerts
- MCP tool calls are also tracked as informational events
- (2) Cursor log parser support via workspaceStorage scanning for AI conversation JSONL/JSON files
- (3) Telegram notification channel using Bot API with "value means enabled" pattern (bot_token + chat_id)
- Also bumped version to 0.3.0, added watchdog dependency, and updated README with MCP injection docs and Telegram setup
- 180 tests passing (+25 new)
