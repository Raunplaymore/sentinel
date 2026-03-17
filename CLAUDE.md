# Sentinel — Claude Guidelines

## 버전 업데이트 체크리스트

버전을 올릴 때 아래 항목을 반드시 확인한다.

### 타이포스쿼팅 감지 패키지 목록 갱신

`sentinel_mac/collectors/typosquatting.py` (또는 해당 패키지 목록 파일)의 인기 패키지 목록을 최신화한다.

**PyPI top 패키지 확인:**
```bash
curl -s "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json" \
  | python3 -c "import json,sys; pkgs=json.load(sys.stdin)['rows']; [print(p['project']) for p in pkgs[:300]]"
```

**npm top 패키지 확인:**
```bash
# npm 상위 패키지는 아래 레지스트리에서 수동 확인
# https://www.npmjs.com/browse/depended
```

목록 변경 사항이 있으면 파일을 업데이트하고 커밋에 포함시킨다.
