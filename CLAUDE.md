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
