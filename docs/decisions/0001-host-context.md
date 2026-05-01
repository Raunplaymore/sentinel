# ADR 0001 — Host Context & Trust API (v0.6)

- **Status**: Accepted
- **Date**: 2026-05-01
- **Scope**: `sentinel_mac/collectors/context.py` (new module, v0.6)
- **Supersedes**: —

## Context

v0.6 메인 테마는 "컨텍스트 인식"으로 false-positive를 줄이는 것이다. 새 모듈
`sentinel_mac/collectors/context.py`가 호스트별 신뢰 신호를 단일 책임으로 다룬다
(`~/.ssh/known_hosts` 매칭 + 빈도 학습). 결과를 `net_tracker` / `agent_log_parser`가
이벤트 detail에 실으면 `AlertEngine`이 알림 강도를 1단계 down-grade한다.

이 ADR은 인터페이스 동결 시점의 결정과 사유를 박제한다. 향후 결정이 추가되면 새 ADR로
이어붙인다 (0002, 0003 ...). 결정 변경은 새 ADR에서 supersede 명시.

본 ADR이 동결하는 것: `context.py`의 공개 API 시그니처 + 영속화 포맷 + config 스키마.
구현 자체는 동결 후 별도 PR.

## Decisions

### D1. TrustLevel은 4단계 — `UNKNOWN / LEARNED / KNOWN / BLOCKED`

**결정**: 3단계(`UNKNOWN/LEARNED/KNOWN`)에 사용자 명시 차단용 `BLOCKED`를 추가한다.

**사유**:
- known_hosts에 등록된 호스트라도 사용자가 "이 bastion은 평소 쓰지만 의심된다"고 판단할
  수 있어야 함. 3단계만으로는 negative override 표현 불가.
- BLOCKED는 v0.6에서 **config의 `blocklist:`로만 설정** (정적 로딩, mutation API 없음).
  CLI는 v0.7에서 동시 추가.
- 시맨틱: BLOCKED는 KNOWN/LEARNED를 우선 차단. 즉 `classify(host)`에서 blocklist 매칭
  시 즉시 BLOCKED 반환. AlertEngine은 BLOCKED → down-grade 안 함 (자동 up-grade는 v0.6
  미적용 — 정책 결정은 별도, 신호만 박아둔다).
- enum 값: `str enum.Enum` 유지. JSON/YAML 직렬화 round-trip.
- ordering: `UNKNOWN(0) < LEARNED(1) < KNOWN(2) < BLOCKED(3)`. 단, `<`/`>` 직접 비교
  금지 — `TrustLevel.rank()` 통해 의도 명시. BLOCKED가 가장 큰 rank인 것은 "가장 강한
  override"의 뜻이며 "가장 신뢰"가 아님.

### D2. `flush()` 주기는 status 보고 주기에 묶음

**결정**: 별도 타이머/스레드 없이 `core.py`의 main loop가 status 보고를 출력하는
주기(기본 60분)에 `host_ctx.flush()`를 호출. shutdown 핸들러에서 한 번 더.

**사유**:
- 별도 타이머 = 스레드 1개 추가 + 종료 시 join 처리 + 테스트 복잡도 증가. 가치 작음.
- 빈도 카운터는 매 관찰마다 dirty flag만 세우고 in-memory 누적. flush가 늦어도 카운트는
  메모리에서 정확. 데몬 비정상 종료 시만 1주기 분량 손실 — 학습 데이터로는 허용 범위.
- atomic rename(`tmp + os.replace`)이라 flush 자체는 빠름. status 주기에 묶어도 stall
  체감 없음.

### D3. CLI 서브커맨드는 v0.7로 미룸 (API는 v0.6에 노출)

**결정**:
- v0.6 노출 API: `forget(host) -> bool`, `iter_observations() -> Iterable[HostObservation]`,
  `is_in_known_hosts(host) -> bool`, `seen_count(host) -> int`.
- v0.6 미노출: `sentinel context forget|block|list|status` CLI 서브커맨드.
- v0.7에서 `commands/context.py` 신규로 wiring.

**사유**:
- API 합의가 빠른 결정이고 CLI는 디자인 폭(서브커맨드 명명/플래그/출력 포맷)이 따로 큼.
  v0.6 scope에서 분리하는 게 합리적.
- 기록 정책 (사용자 요청): 이 결정 자체를 잊지 않게 다음 3곳에 흔적:
  1. `context.py` 모듈 docstring 끝에 "v0.6: API only. CLI deferred to v0.7. See
     ADR 0001." 1줄
  2. `CHANGELOG.md [Unreleased]`에 명시
  3. 본 ADR (정전점)
- v0.7 진입 시 본 ADR을 supersede 하는 새 ADR(예: 0003)에서 CLI 인터페이스 동결.

### D4. v0.6 적용 범위는 SSH/SCP만 — WebFetch 미적용

**결정**: `agent_log_parser.py`에서 SSH/SCP 패턴 매치 시에만 host 추출 → context 조회 →
가중치 적용. WebFetch URL의 호스트는 v0.6에서 컨텍스트 미적용.

**사유**:
- WebFetch 대상 사이트는 다양성이 크고(api/문서/CDN/raw 콘텐츠 등) 빈도 임계값(N=5)으로
  의미 있는 trust 신호 도출 어려움.
- SSH/SCP는 사용자가 의식적으로 접속하는 호스트라 known_hosts와 빈도 모두 강한 신호.
- WebFetch 컨텍스트 적용은 별도 신호(예: TLS 인증서, eTLD+1 정규화) 필요 — v0.7+ 별도
  검토.

**중요 제약**: `pipe to shell` / `dangerous recursive delete` / `eval(` / `base64 -d` /
`nc -l` / 인라인 코드 실행 카테고리는 host와 무관하게 down-grade **금지**. host trust로
다운그레이드 가능한 카테고리는 SSH/SCP **만**. agent_log_parser 통합 코드의 화이트리스트
강제 (공격자가 자기 도메인 빈도 올려 자동 trust 유도하는 벡터 차단).

### D5. 다운로드 추적은 v0.7 편입

**결정**: `curl/wget`이 파일을 받는 케이스 (`-o`, `--output`, `>`, `git clone`)에서
URL과 출력 경로를 짝지어 SecurityEvent로 기록하는 기능은 v0.7 부수 작업으로 편입.

**사유**:
- 실재하는 gap. `curl https://x/y -o /tmp/x` 형태는 현 high-risk 패턴에 안 걸리고
  FSWatcher는 source URL을 모름.
- v0.6에 추가하면 scope creep — 4번째 트랙 = 인터페이스 합의 다시. 테마 불일치(컨텍스트
  인식과 다른 방향).
- v0.7 메인(`--report` 필터 확장)과 자연 결합: `--type download` 필터 + `agent_log_parser`
  변경이 같은 파일이라 v0.6 머지 후 충돌 적게 들어감.
- 추정: ~80~120 LOC. 별 ADR(0002)에서 다운로드 추적 시그니처 동결.

## Consequences

### Positive
- v0.6 트랙 A/B/C가 `context.py`의 freeze된 시그니처를 import해서 병렬 작업 가능.
- BLOCKED 추가로 보안 의식 사용자에게 negative override 옵션 제공.
- 기록 3곳(docstring + CHANGELOG + ADR) → 결정이 코드/릴리스/장기 문서 모두에 박힘.

### Negative / 수용한 trade-off
- BLOCKED 추가로 enum/classify 분기 1개 + 테스트 케이스 ~5개 증가.
- WebFetch 미적용으로 일부 false-positive 잔존 — v0.7+ 검토.
- 다운로드 추적 v0.7 미룸으로 v0.6 ~ v0.7 사이 기간 동안 `curl -o` 류 gap 잔존.
- flush 주기 = status 주기 = 기본 60분이라 데몬 비정상 종료 시 최대 60분 학습 손실.
  학습 데이터 특성상 허용.

### Follow-ups
- ADR 0002 (예정): 다운로드 추적 시그니처 (`agent_download` SecurityEvent + FSWatcher join).
- ADR 0003 (예정): `sentinel context` CLI 서브커맨드 (v0.7).
- ADR 0004 (예정 / 보류): WebFetch 컨텍스트 적용 — 별 신호 필요.

## Frozen API surface

본 ADR이 동결하는 시그니처는 `sentinel_mac/collectors/context.py`의 skeleton 파일에
docstring + `raise NotImplementedError`로 박제한다. 구현 PR은 본체만 채우고 시그니처는
변경 금지. 시그니처 변경 필요 시 본 ADR을 supersede하는 새 ADR 필수.

## Frozen config schema

`config.example.yaml`에 추가될 `security.context_aware:` 섹션 (디폴트 OFF):

```yaml
security:
  context_aware:
    enabled: false
    auto_trust_after_seen: 5      # >= 2 강제
    learning_window_days: 30
    dedup_window_seconds: 3600
    max_tracked_hosts: 5000
    known_hosts_path: "~/.ssh/known_hosts"  # ""이면 비활성
    cache_path: ""                # ""이면 XDG 디폴트
    blocklist: []                 # ["evil.com", "*.suspicious.tld"]
```

설정 키 변경/추가는 supersede ADR 필수.
