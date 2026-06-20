# web-attack-log-analyzer

웹 공격 시나리오를 재현하고 서버 로그를 분석하여 침해 흔적과 대응 방안을 리포트로 정리하는 실습 프로젝트입니다.

## 프로젝트 목적

실습용 웹 서버를 직접 실행하고, Brute Force, SQL Injection, XSS, Path Traversal, 스캐너 요청 등 대표적인 웹 공격 시나리오를 재현한 뒤 Access 로그와 Login 로그를 분석합니다.

분석 결과는 탐지 룰 ID, 위험도, 신뢰도, 증거, 권장 대응을 포함한 TXT, Markdown, JSON 리포트로 생성됩니다.

## 주요 기능

- Flask 기반 실습용 로그인 서버
- Access 로그 및 Login 로그 수집
- 로컬 테스트 공격 트래픽 생성
- SQL Injection, XSS, Path Traversal 탐지
- 관리자 페이지 접근, 스캐너 User-Agent, 반복 404 탐지
- 반복 로그인 실패 및 실패 후 성공 로그인 탐지
- TXT, Markdown, JSON 리포트 출력
- CLI 옵션 기반 분석 설정
- pytest 기반 탐지 및 CLI 테스트

## 프로젝트 구조

```text
app/
  app.py                         # 실습용 Flask 서버
  templates/login.html           # 로그인 페이지
analyzer/
  web_log_analyzer.py            # 로그 분석기
  rules.json                     # 탐지 룰 설정 파일
scripts/
  generate_test_traffic.py       # 로컬 테스트 트래픽 생성기
logs/
  access.log                     # HTTP 요청 로그
  login.log                      # 로그인 이벤트 로그
tests/
  test_web_log_analyzer.py       # 분석기 테스트
result/                          # 분석 리포트 출력 경로
```

## 설치

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 실습 서버 실행

```bash
python app/app.py
```

기본 서버 주소는 `http://127.0.0.1:5000`입니다.

로그인 실습 계정:

```text
admin / password123
```

## 테스트 트래픽 생성

서버를 실행한 상태에서 다른 터미널을 열고 실행합니다.

```bash
python scripts/generate_test_traffic.py
```

특정 로컬 주소를 지정할 수도 있습니다.

```bash
python scripts/generate_test_traffic.py http://127.0.0.1:5000
```

이 스크립트는 안전을 위해 `localhost` 또는 `127.0.0.1` 대상으로만 실행됩니다.

## 로그 분석 실행

기본 로그 경로와 기본 출력 경로를 사용하려면 다음처럼 실행합니다.

```bash
python analyzer/web_log_analyzer.py
```

옵션을 명시해서 실행할 수도 있습니다.

```bash
python analyzer/web_log_analyzer.py \
  --access-log logs/access.log \
  --login-log logs/login.log \
  --threshold 5 \
  --format all \
  --output-dir result
```

## CLI 옵션

```text
--access-log   Access 로그 파일 경로
--access-format Access 로그 포맷: custom, nginx
--login-log    Login 로그 파일 경로
--threshold    반복 이벤트 탐지 기준
--format       출력 포맷: txt, md, json, csv, all
--output-dir   리포트 저장 디렉터리
--rules-file   탐지 룰 JSON 파일 경로
--severity     위험도 필터: HIGH, MEDIUM, LOW
--attack-type  공격 유형 필터
--ip           IP 필터
```

예시:

```bash
python analyzer/web_log_analyzer.py --format json
python analyzer/web_log_analyzer.py --format txt,md
python analyzer/web_log_analyzer.py --format csv
python analyzer/web_log_analyzer.py --threshold 10 --output-dir result
python analyzer/web_log_analyzer.py --rules-file analyzer/rules.json
python analyzer/web_log_analyzer.py --severity HIGH --format json
python analyzer/web_log_analyzer.py --attack-type "SQL Injection" --format md
python analyzer/web_log_analyzer.py --ip 127.0.0.1 --format json
python analyzer/web_log_analyzer.py --access-log logs/nginx_access.log --access-format nginx --format json
```

## 리포트 출력

분석 결과는 `result/` 아래에 생성됩니다.

```text
web_attack_detection_result_*.txt
web_attack_detection_report_*.md
web_attack_detection_report_*.json
web_attack_detection_findings_*.csv
```

각 finding에는 다음 정보가 포함됩니다.

```text
rule_id
severity
confidence
source_log
attack_type
timestamp
ip
evidence
reason
response
```

JSON과 Markdown 리포트에는 전체 위험도, 주요 공격 유형, 주요 의심 IP, 우선 대응을 요약한 Executive Summary와 시간순 탐지 이벤트를 정리한 `timeline`이 포함됩니다. 로그인 실패 반복처럼 집계형으로 생성되는 이벤트는 timestamp가 `-`이므로 타임라인에서는 제외됩니다.

## 대시보드 확인

Flask 서버를 실행한 뒤 브라우저에서 `/dashboard`로 접속하면 최신 JSON 리포트를 요약 화면으로 확인할 수 있습니다. 대시보드는 요청 수, 탐지 수, Executive Summary, 위험도, 공격 유형, 요청 IP Top 5, Timeline, 최근 탐지 결과, CSV Preview를 표시합니다.

```bash
python app/app.py
```

```text
http://127.0.0.1:5000/dashboard
```

브라우저에서 `/upload`로 접속하면 Access 로그와 Login 로그를 업로드해 바로 분석할 수 있습니다. 분석이 끝나면 TXT, Markdown, JSON, CSV 리포트를 생성하고 새 JSON 리포트가 선택된 대시보드로 이동합니다.

```text
http://127.0.0.1:5000/upload
```

`/reports`에서는 생성된 JSON 리포트 이력을 목록으로 확인하고, 각 리포트의 대시보드 보기, 다운로드 링크, 리포트 묶음 삭제 기능을 사용할 수 있습니다. 삭제 전에는 확인 창이 표시됩니다.

```text
http://127.0.0.1:5000/reports
```

대시보드는 `result/web_attack_detection_report_*.json` 중 가장 최신 파일을 기본으로 읽으며, Report 선택 상자에서 이전 JSON 리포트도 확인할 수 있습니다. 같은 타임스탬프의 JSON, Markdown, TXT, CSV 리포트가 있으면 대시보드에서 바로 다운로드할 수 있고, CSV 탐지 결과는 상위 행을 미리보기로 확인할 수 있습니다. JSON 리포트가 없다면 먼저 분석기를 실행합니다.
선택한 JSON 리포트가 비어 있거나 형식이 깨진 경우에는 서버 오류 대신 대시보드 상단에 읽기 실패 메시지를 표시합니다.

```bash
python analyzer/web_log_analyzer.py --format all
```

대시보드에서도 필터를 적용할 수 있습니다.

```text
http://127.0.0.1:5000/dashboard?severity=HIGH
http://127.0.0.1:5000/dashboard?attack_type=SQL%20Injection
http://127.0.0.1:5000/dashboard?severity=HIGH&ip=127.0.0.1
http://127.0.0.1:5000/dashboard?report=web_attack_detection_report_20260620_160000.json
```

필터와 리포트 선택 상태는 URL에 반영되므로, 대시보드의 현재 보기 링크를 공유하면 같은 분석 화면을 다시 확인할 수 있습니다.

## 탐지 룰

패턴 기반 탐지 룰은 `analyzer/rules.json`에서 관리합니다. 룰 파일을 수정하면 분석기 코드를 바꾸지 않고도 탐지 패턴, 위험도, 신뢰도, 대응 문구를 조정할 수 있습니다.
Flask 서버 실행 후 `/rules`로 접속하면 Rule ID, 공격 유형, 위험도, 신뢰도, 탐지 패턴, 권장 대응을 웹 화면에서 조회할 수 있습니다. Rule ID, 공격 유형, 패턴 검색과 위험도, 매칭 방식 필터도 지원합니다.

```text
http://127.0.0.1:5000/rules
```

룰 예시:

```json
{
  "rule_id": "SQLI-001",
  "attack_type": "SQL Injection",
  "severity": "HIGH",
  "confidence": "HIGH",
  "source": "request",
  "match_type": "contains",
  "evidence_key": "matched_pattern",
  "description": "SQL Injection 의심 문자열 탐지",
  "patterns": ["' or", "union select"],
  "reason": "요청 경로 또는 쿼리 문자열에서 SQL Injection 의심 패턴 발견",
  "response": "입력값 검증, Prepared Statement 사용 여부, WAF 룰을 점검합니다."
}
```

`source`는 `request` 또는 `user_agent`를 사용할 수 있습니다.
`match_type`은 `contains` 또는 `regex`를 사용할 수 있습니다. 생략하면 `contains`로 처리되며, `regex`를 사용하면 Python 정규식으로 패턴을 탐지합니다.

| Rule ID | 탐지 유형 | 위험도 |
|---|---|---|
| SQLI-001 | SQL Injection | HIGH |
| XSS-001 | XSS | HIGH |
| PATH-001 | Path Traversal | HIGH |
| ADMIN-001 | Admin Page Access | MEDIUM |
| SCAN-001 | Suspicious User-Agent | MEDIUM |
| SCAN-002 | Repeated 404 | MEDIUM |
| AUTH-001 | Repeated Login Failure | MEDIUM/HIGH |
| AUTH-002 | Successful Login After Failures | HIGH |

## 테스트 실행

```bash
pytest
```

특정 테스트 파일만 실행하려면:

```bash
pytest tests/test_web_log_analyzer.py
```

현재 테스트는 공격 룰 탐지, 로그인 이벤트 탐지, JSON 포맷 출력, 잘못된 포맷 에러 처리를 검증합니다.

## 주의사항

이 프로젝트는 보안 실습과 로그 분석 학습을 위한 로컬 전용 프로젝트입니다. 테스트 트래픽 생성기는 외부 대상이 아닌 로컬 테스트 서버에만 사용해야 합니다.
