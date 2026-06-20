import csv
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_SCRIPT = PROJECT_ROOT / "analyzer" / "web_log_analyzer.py"

sys.path.insert(0, str(PROJECT_ROOT))

from analyzer import web_log_analyzer


def write_lines(path: Path, lines: list[str]):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_analyze_access_log_detects_attack_rule_ids(tmp_path):
    access_log = tmp_path / "access.log"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/login" query="id=1%27%20OR%20%271%27%3D%271" status=200 user_agent="Mozilla/5.0"',
            '2026-06-20 10:00:01 HTTP_REQUEST ip=10.0.0.2 method=GET path="/search" query="q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" status=404 user_agent="Mozilla/5.0"',
            '2026-06-20 10:00:02 HTTP_REQUEST ip=10.0.0.3 method=GET path="/download" query="file=..%2F..%2Fetc%2Fpasswd" status=404 user_agent="Mozilla/5.0"',
        ],
    )

    result = web_log_analyzer.analyze_access_log(access_log, threshold=5)
    rule_ids = {finding["rule_id"] for finding in result["findings"]}

    assert {"SQLI-001", "XSS-001", "PATH-001"}.issubset(rule_ids)


def test_analyze_nginx_access_log_detects_attack_rule_ids(tmp_path):
    access_log = tmp_path / "nginx_access.log"
    write_lines(
        access_log,
        [
            '10.0.0.1 - - [20/Jun/2026:10:00:00 +0900] "GET /login?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
            '10.0.0.2 - - [20/Jun/2026:10:00:01 +0900] "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 404 123 "-" "Mozilla/5.0"',
        ],
    )

    result = web_log_analyzer.analyze_access_log(access_log, threshold=5, access_format="nginx")
    rule_ids = {finding["rule_id"] for finding in result["findings"]}

    assert {"SQLI-001", "XSS-001"}.issubset(rule_ids)


def test_analyze_access_log_supports_regex_rule_matching(tmp_path):
    access_log = tmp_path / "access.log"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/search" query="q=UNION%20ALL%20SELECT%20password" status=200 user_agent="Mozilla/5.0"',
        ],
    )
    rules = [
        {
            "rule_id": "REGEX-001",
            "attack_type": "Regex SQL Injection",
            "severity": "HIGH",
            "confidence": "HIGH",
            "source": "request",
            "match_type": "regex",
            "evidence_key": "matched_pattern",
            "description": "Regex 기반 SQL Injection 탐지",
            "patterns": [r"union\s+(all\s+)?select"],
            "reason": "정규식 기반 SQL Injection 패턴 발견",
            "response": "쿼리 파라미터 검증을 확인합니다.",
        },
    ]

    result = web_log_analyzer.analyze_access_log(access_log, threshold=5, rules=rules)

    assert result["findings"][0]["rule_id"] == "REGEX-001"
    assert result["findings"][0]["evidence"] == r"matched_pattern=union\s+(all\s+)?select"


def test_load_detection_rules_rejects_invalid_match_type(tmp_path):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "BAD-001",
                        "attack_type": "Bad Rule",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "source": "request",
                        "match_type": "wildcard",
                        "evidence_key": "matched_pattern",
                        "description": "잘못된 매칭 방식",
                        "patterns": ["bad"],
                        "reason": "잘못된 룰",
                        "response": "룰 설정을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    try:
        web_log_analyzer.load_detection_rules(rules_file)
    except ValueError as error:
        assert "match_type" in str(error)
    else:
        raise AssertionError("invalid match_type should raise ValueError")


def test_analyze_login_log_detects_repeated_failures_and_success(tmp_path):
    login_log = tmp_path / "login.log"
    write_lines(
        login_log,
        [
            '2026-06-20 10:00:00 LOGIN_FAIL ip=10.0.0.10 id=admin user_agent="Mozilla/5.0"',
            '2026-06-20 10:00:01 LOGIN_FAIL ip=10.0.0.10 id=admin user_agent="Mozilla/5.0"',
            '2026-06-20 10:00:02 LOGIN_FAIL ip=10.0.0.10 id=admin user_agent="Mozilla/5.0"',
            '2026-06-20 10:00:03 LOGIN_SUCCESS ip=10.0.0.10 id=admin user_agent="Mozilla/5.0"',
        ],
    )

    result = web_log_analyzer.analyze_login_log(login_log, threshold=3)
    rule_ids = {finding["rule_id"] for finding in result["findings"]}

    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids


def test_cli_format_json_creates_only_json_report(tmp_path):
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    output_dir = tmp_path / "result"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/login" query="id=1%27%20OR%20%271%27%3D%271" status=200 user_agent="Mozilla/5.0"',
        ],
    )
    write_lines(login_log, [])

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(access_log),
            "--login-log",
            str(login_log),
            "--threshold",
            "5",
            "--format",
            "json",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_files = list(output_dir.iterdir())
    assert len(output_files) == 1
    assert output_files[0].suffix == ".json"

    payload = json.loads(output_files[0].read_text(encoding="utf-8"))
    assert payload["summary"]["total_findings"] == 1
    assert payload["analysis_info"]["rules_file"].endswith("rules.json")
    assert payload["findings"][0]["rule_id"] == "SQLI-001"
    assert payload["timeline"][0]["rule_id"] == "SQLI-001"
    assert all(item["timestamp"] != "-" for item in payload["timeline"])
    assert payload["executive_summary"]["overall_risk"] == "HIGH"
    assert payload["executive_summary"]["top_attack_type"] == "SQL Injection"


def test_cli_format_csv_creates_findings_csv_report(tmp_path):
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    output_dir = tmp_path / "result"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/login" query="id=1%27%20OR%20%271%27%3D%271" status=200 user_agent="Mozilla/5.0"',
        ],
    )
    write_lines(login_log, [])

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(access_log),
            "--login-log",
            str(login_log),
            "--format",
            "csv",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_files = list(output_dir.iterdir())
    assert len(output_files) == 1
    assert output_files[0].name.startswith("web_attack_detection_findings_")
    assert output_files[0].suffix == ".csv"

    with output_files[0].open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert rows[0]["rule_id"] == "SQLI-001"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["attack_type"] == "SQL Injection"
    assert rows[0]["ip"] == "10.0.0.1"


def test_cli_uses_custom_rules_file(tmp_path):
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    rules_file = tmp_path / "rules.json"
    output_dir = tmp_path / "result"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/health" query="token=custom-attack" status=200 user_agent="Mozilla/5.0"',
        ],
    )
    write_lines(login_log, [])
    rules_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "CUSTOM-001",
                        "attack_type": "Custom Attack",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "source": "request",
                        "evidence_key": "matched_pattern",
                        "description": "커스텀 공격 패턴 탐지",
                        "patterns": ["custom-attack"],
                        "reason": "커스텀 공격 패턴 발견",
                        "response": "커스텀 룰 대응 절차를 확인합니다.",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(access_log),
            "--login-log",
            str(login_log),
            "--rules-file",
            str(rules_file),
            "--format",
            "json",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_file = next(output_dir.glob("*.json"))
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["analysis_info"]["rules_file"] == str(rules_file)
    assert payload["findings"][0]["rule_id"] == "CUSTOM-001"


def test_cli_uses_nginx_access_format(tmp_path):
    access_log = tmp_path / "nginx_access.log"
    login_log = tmp_path / "login.log"
    output_dir = tmp_path / "result"
    write_lines(
        access_log,
        [
            '10.0.0.1 - - [20/Jun/2026:10:00:00 +0900] "GET /login?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
        ],
    )
    write_lines(login_log, [])

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(access_log),
            "--access-format",
            "nginx",
            "--login-log",
            str(login_log),
            "--format",
            "json",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_file = next(output_dir.glob("*.json"))
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["analysis_info"]["access_format"] == "nginx"
    assert payload["findings"][0]["rule_id"] == "SQLI-001"


def test_cli_filters_findings_by_severity(tmp_path):
    output_dir = tmp_path / "result"

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(PROJECT_ROOT / "logs" / "access.log"),
            "--login-log",
            str(PROJECT_ROOT / "logs" / "login.log"),
            "--severity",
            "HIGH",
            "--format",
            "json",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_file = next(output_dir.glob("*.json"))
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["analysis_info"]["filters"]["severities"] == ["HIGH"]
    assert payload["findings"]
    assert {finding["severity"] for finding in payload["findings"]} == {"HIGH"}
    assert payload["summary"]["risk_counts"]["MEDIUM"] == 0


def test_cli_filters_findings_by_attack_type(tmp_path):
    output_dir = tmp_path / "result"

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(PROJECT_ROOT / "logs" / "access.log"),
            "--login-log",
            str(PROJECT_ROOT / "logs" / "login.log"),
            "--attack-type",
            "SQL Injection",
            "--format",
            "json",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_file = next(output_dir.glob("*.json"))
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["analysis_info"]["filters"]["attack_types"] == ["SQL Injection"]
    assert payload["findings"]
    assert {finding["attack_type"] for finding in payload["findings"]} == {"SQL Injection"}


def test_cli_markdown_report_includes_timeline_section(tmp_path):
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    output_dir = tmp_path / "result"
    write_lines(
        access_log,
        [
            '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET path="/login" query="id=1%27%20OR%20%271%27%3D%271" status=200 user_agent="Mozilla/5.0"',
        ],
    )
    write_lines(login_log, [])

    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--access-log",
            str(access_log),
            "--login-log",
            str(login_log),
            "--format",
            "md",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0

    output_file = next(output_dir.glob("*.md"))
    report = output_file.read_text(encoding="utf-8")
    assert "## 3. Executive Summary" in report
    assert "## 4. Timeline" in report
    assert "SQLI-001" in report
    assert "2026-06-20 10:00:00" in report


def test_cli_rejects_invalid_format(tmp_path):
    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER_SCRIPT),
            "--format",
            "xml",
            "--output-dir",
            str(tmp_path / "result"),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "지원하지 않는 format" in completed.stderr
