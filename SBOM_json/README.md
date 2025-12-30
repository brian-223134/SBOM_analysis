## SBOM JSON 파일 안내

- 이 디렉터리에는 프로젝트별 SBOM 결과 JSON 파일을 보관합니다.
- 파일명은 `{프로젝트이름}_{SBOM양식}.json` 규칙을 따릅니다.
  - `프로젝트이름`: 공백 대신 하이픈(`-`) 또는 언더스코어(`_`) 사용 권장
  - `SBOM양식`: 예) `cyclonedx`, `spdx`, `github`, `hatbom` 등 생성된 포맷 명칭

### 예시

- `my-service_cyclonedx.json`
- `web-portal_spdx.json`
- `cmdb-back_github.json`
- `cmdb-back_hatbom.json`

### 작성 가이드

- 한 프로젝트가 여러 SBOM 포맷을 가질 수 있으므로 포맷을 명확히 구분합니다.
- 동일 프로젝트/포맷을 재생성할 때는 덮어쓰지 않고 날짜나 버전을 추가합니다. 예: `my-service_2024-12-30_cyclonedx.json`
- 파일 내용은 각 SBOM 표준(예: CycloneDX, SPDX)의 스키마를 준수하도록 생성합니다.
