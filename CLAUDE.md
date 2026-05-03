# Sentinel — Claude Guidelines

## 버전 업데이트 체크리스트

버전을 올릴 때 아래 항목을 반드시 확인한다.

### 타이포스쿼팅 감지 패키지 목록 갱신

`sentinel_mac/collectors/typosquatting.py` (또는 해당 패키지 목록 파일)의 인기 패키지 목록을 최신화한다.

**PyPI top 패키지 확인:**
```bash
# -L 필수: hugovk.github.io → hugovk.dev (301 redirect)
curl -sL "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json" \
  | python3 -c "import json,sys; pkgs=json.load(sys.stdin)['rows']; [print(p['project']) for p in pkgs[:300]]"
```

**npm top 패키지 확인:**
```bash
# npm 상위 패키지는 아래 레지스트리에서 수동 확인
# https://www.npmjs.com/browse/depended
```

목록 변경 사항이 있으면 파일을 업데이트하고 커밋에 포함시킨다.

**출처 신뢰 모델 (typosquatting 리스트):**
- 원천 데이터: PyPI BigQuery 공개 데이터셋(Google 호스팅, 공식). `pypinfo` 도구로 추출
- 가공·배포: github.com/hugovk/top-pypi-packages — Hugo van Kemenade(CPython core dev)가 월 1회 cron으로 갱신. 공식 PSF/PyPA 채널은 아님
- 사용 방식: 위 명령으로 받은 결과를 코드에 **하드코딩된 set으로 freeze** (런타임 fetch ✗) → 빌드된 버전은 출처 인프라에 향후 변동/침해가 생겨도 영향 없음
- 더 공신력 높은 대안이 필요하면 BigQuery `bigquery-public-data.pypi.file_downloads` 직접 쿼리 (GCP 계정 필요)

<!-- MY-AGENT-CREWS-START -->
## My Agent Crews Routing (required)

`.claude/crews-routing.md`가 존재하면 **세션에서 첫 번째 요청을 받는 즉시 이 파일을
Read 도구로 읽어라**. Read 전에는 어떤 코드 변경이나 에이전트 호출도 하지 않는다.

- "간단한 수정이니 건너뛰어도 되겠지"라는 자기 판단 금지
- "어차피 별 내용 없겠지"라는 추측 금지
- 이미 설치된 프로젝트에서 Read를 건너뛰는 것은 **프로젝트 규칙 위반**이다

crews-routing.md는 이 프로젝트의 에이전트 라우팅/Quick Plan/small fix 규칙을
정의한다. Read 없이는 규칙을 알 수 없으므로 반드시 먼저 읽는다.

파일이 없으면 이 섹션 전체를 무시하고 기본 동작 — my-agent-crews 미설치 환경에서는 정상.

> 설치 방법: <repo-url>
<!-- MY-AGENT-CREWS-END -->
