import json
import sys
from pathlib import Path
from io import BytesIO


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import app as app_module


def test_upload_page_renders_form(monkeypatch):
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/upload")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Upload Logs" in body
    assert 'name="access_log"' in body
    assert 'name="login_log"' in body
    assert 'name="threshold"' in body


def test_upload_analyzes_logs_and_redirects_to_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    access_log = (
        '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET '
        'path="/login" query="id=1%27%20OR%20%271%27%3D%271" '
        'status=200 user_agent="Mozilla/5.0"\n'
    )

    client = app_module.app.test_client()
    response = client.post(
        "/upload",
        data={
            "access_format": "custom",
            "threshold": "5",
            "access_log": (BytesIO(access_log.encode("utf-8")), "access.log"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert "/dashboard?report=web_attack_detection_report_" in response.headers["Location"]

    json_report = next(tmp_path.glob("web_attack_detection_report_*.json"))
    payload = json.loads(json_report.read_text(encoding="utf-8"))

    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["rule_id"] == "SQLI-001"
    assert next(tmp_path.glob("web_attack_detection_report_*.md")).is_file()
    assert next(tmp_path.glob("web_attack_detection_result_*.txt")).is_file()
    assert next(tmp_path.glob("web_attack_detection_findings_*.csv")).is_file()


def test_upload_requires_at_least_one_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.post(
        "/upload",
        data={
            "access_format": "custom",
            "threshold": "5",
        },
        content_type="multipart/form-data",
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Access 로그 또는 Login 로그 중 하나 이상을 업로드해야 합니다." in body
    assert not list(tmp_path.iterdir())


def test_reports_page_renders_report_history(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    markdown_file = tmp_path / "web_attack_detection_report_20260620_160000.md"
    csv_file = tmp_path / "web_attack_detection_findings_20260620_160000.csv"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_findings": 3,
                    "suspicious_ip_count": 2,
                },
                "executive_summary": {
                    "overall_risk": "HIGH",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    markdown_file.write_text("# report", encoding="utf-8")
    csv_file.write_text("rule_id,severity\nSQLI-001,HIGH\n", encoding="utf-8")

    client = app_module.app.test_client()
    response = client.get("/reports")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Report History" in body
    assert report_file.name in body
    assert "2026-06-20 16:00:00" in body
    assert "HIGH" in body
    assert "/dashboard?report=web_attack_detection_report_20260620_160000.json" in body
    assert "/reports/web_attack_detection_report_20260620_160000.md" in body
    assert "/reports/web_attack_detection_findings_20260620_160000.csv" in body
    assert "onsubmit=\"return confirm(" in body
    assert "JSON, Markdown, TXT, CSV 파일을 삭제할까요?" in body


def test_reports_page_marks_invalid_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text("{invalid json", encoding="utf-8")

    client = app_module.app.test_client()
    response = client.get("/reports")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert report_file.name in body
    assert "ERROR" in body
    assert "JSON 리포트를 읽을 수 없습니다" in body


def test_reports_page_can_delete_report_bundle(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    json_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    markdown_file = tmp_path / "web_attack_detection_report_20260620_160000.md"
    txt_file = tmp_path / "web_attack_detection_result_20260620_160000.txt"
    csv_file = tmp_path / "web_attack_detection_findings_20260620_160000.csv"
    json_file.write_text("{}", encoding="utf-8")
    markdown_file.write_text("# report", encoding="utf-8")
    txt_file.write_text("report", encoding="utf-8")
    csv_file.write_text("rule_id,severity\n", encoding="utf-8")

    client = app_module.app.test_client()
    response = client.post("/reports/delete", data={"filename": json_file.name})

    assert response.status_code == 302
    assert response.headers["Location"] == "/reports"
    assert not json_file.exists()
    assert not markdown_file.exists()
    assert not txt_file.exists()
    assert not csv_file.exists()


def test_reports_delete_rejects_unexpected_filename(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.post("/reports/delete", data={"filename": "../app.py"})

    assert response.status_code == 404


def test_rules_page_renders_detection_rules(tmp_path, monkeypatch):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "SQLI-001",
                        "attack_type": "SQL Injection",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "source": "request",
                        "match_type": "regex",
                        "evidence_key": "matched_pattern",
                        "description": "SQL Injection 의심 문자열 탐지",
                        "patterns": ["' or", "union select"],
                        "reason": "SQL Injection 의심 패턴 발견",
                        "response": "Prepared Statement 사용 여부를 점검합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "RULES_FILE", rules_file)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/rules")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Detection Rules" in body
    assert "SQLI-001" in body
    assert "SQL Injection" in body
    assert "regex" in body
    assert "union select" in body
    assert "Prepared Statement 사용 여부를 점검합니다." in body


def test_rules_page_filters_rules_by_query_parameters(tmp_path, monkeypatch):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "SQLI-001",
                        "attack_type": "SQL Injection",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "source": "request",
                        "match_type": "regex",
                        "evidence_key": "matched_pattern",
                        "description": "SQL Injection 의심 문자열 탐지",
                        "patterns": ["union select"],
                        "reason": "SQL Injection 의심 패턴 발견",
                        "response": "Prepared Statement 사용 여부를 점검합니다.",
                    },
                    {
                        "rule_id": "SCAN-001",
                        "attack_type": "Suspicious User-Agent",
                        "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "source": "user_agent",
                        "match_type": "contains",
                        "evidence_key": "matched_user_agent",
                        "description": "스캐너 User-Agent 탐지",
                        "patterns": ["sqlmap"],
                        "reason": "스캐너 의심 User-Agent 탐지",
                        "response": "해당 IP 요청 패턴을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "RULES_FILE", rules_file)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/rules?severity=HIGH&match_type=regex&q=sqli")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "SQLI-001" in body
    assert "SCAN-001" not in body
    assert '<option value="HIGH" selected>HIGH</option>' in body
    assert '<option value="regex" selected>regex</option>' in body
    assert 'value="sqli"' in body


def test_rules_page_handles_invalid_rules_file(tmp_path, monkeypatch):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text("{invalid json", encoding="utf-8")
    monkeypatch.setattr(app_module, "RULES_FILE", rules_file)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/rules")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "탐지 룰 파일을 읽을 수 없습니다" in body
    assert "표시할 탐지 룰이 없습니다." in body


def test_dashboard_renders_live_analysis_from_current_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    access_log.write_text(
        '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET '
        'path="/login" query="id=1%27%20OR%20%271%27%3D%271" '
        'status=200 user_agent="Mozilla/5.0"\n',
        encoding="utf-8",
    )
    login_log.write_text("", encoding="utf-8")
    monkeypatch.setattr(app_module, "ACCESS_LOG_FILE", access_log)
    monkeypatch.setattr(app_module, "LOGIN_LOG_FILE", login_log)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/dashboard")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "실시간 분석" in body
    assert "SQLI-001" in body
    assert "CSV Preview" in body


def test_dashboard_renders_generate_report_button(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    access_log = tmp_path / "access.log"
    login_log = tmp_path / "login.log"
    access_log.write_text("", encoding="utf-8")
    login_log.write_text("", encoding="utf-8")
    monkeypatch.setattr(app_module, "ACCESS_LOG_FILE", access_log)
    monkeypatch.setattr(app_module, "LOGIN_LOG_FILE", login_log)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/dashboard")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'action="/reports/generate"' in body
    assert "현재 분석 리포트 저장" in body


def test_generate_report_from_current_logs_redirects_to_dashboard(tmp_path, monkeypatch):
    result_dir = tmp_path / "result"
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    access_log = log_dir / "access.log"
    login_log = log_dir / "login.log"
    access_log.write_text(
        '2026-06-20 10:00:00 HTTP_REQUEST ip=10.0.0.1 method=GET '
        'path="/login" query="id=1%27%20OR%20%271%27%3D%271" '
        'status=200 user_agent="Mozilla/5.0"\n',
        encoding="utf-8",
    )
    login_log.write_text("", encoding="utf-8")
    monkeypatch.setattr(app_module, "RESULT_DIR", result_dir)
    monkeypatch.setattr(app_module, "ACCESS_LOG_FILE", access_log)
    monkeypatch.setattr(app_module, "LOGIN_LOG_FILE", login_log)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.post("/reports/generate")

    assert response.status_code == 302
    assert "/dashboard?report=web_attack_detection_report_" in response.headers["Location"]

    json_report = next(result_dir.glob("web_attack_detection_report_*.json"))
    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["findings"][0]["rule_id"] == "SQLI-001"
    assert next(result_dir.glob("web_attack_detection_report_*.md")).is_file()
    assert next(result_dir.glob("web_attack_detection_result_*.txt")).is_file()
    assert next(result_dir.glob("web_attack_detection_findings_*.csv")).is_file()


def test_dashboard_renders_latest_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 10,
                    "total_login_events": 4,
                    "total_findings": 2,
                    "suspicious_ip_count": 2,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1", "10.0.0.2"],
                    "request_count_by_ip": {"10.0.0.1": 10, "10.0.0.2": 4},
                },
                "timeline": [
                    {
                        "timestamp": "2026-06-20 16:00:00",
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                    },
                    {
                        "timestamp": "2026-06-20 16:00:01",
                        "rule_id": "SCAN-002",
                        "severity": "MEDIUM",
                        "attack_type": "Repeated 404",
                        "ip": "10.0.0.2",
                        "path": "-",
                        "evidence": "status_404_count=5, threshold=5",
                    },
                ],
                "findings": [
                    {
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                        "response": "입력값 검증을 확인합니다.",
                    },
                    {
                        "rule_id": "SCAN-002",
                        "severity": "MEDIUM",
                        "attack_type": "Repeated 404",
                        "ip": "10.0.0.2",
                        "path": "-",
                        "evidence": "status_404_count=5, threshold=5",
                        "response": "스캔 행위 가능성을 확인합니다.",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "web_attack_detection_report_20260620_160000.json" in body
    assert "SQLI-001" in body
    assert "10.0.0.1" in body
    assert "요청 IP Top 5" in body
    assert "Repeated 404" in body
    assert "Timeline" in body
    assert "2026-06-20 16:00:00" in body


def test_dashboard_renders_executive_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 10,
                    "total_login_events": 4,
                    "total_findings": 1,
                    "suspicious_ip_count": 1,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                },
                "executive_summary": {
                    "overall_risk": "HIGH",
                    "top_attack_type": "SQL Injection",
                    "top_suspicious_ip": "10.0.0.1",
                    "priority_action": "WAF 룰과 입력값 검증을 우선 점검합니다.",
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1"],
                    "request_count_by_ip": {"10.0.0.1": 10},
                },
                "timeline": [],
                "findings": [
                    {
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                        "response": "입력값 검증을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Executive Summary" in body
    assert "전체 위험도" in body
    assert "SQL Injection" in body
    assert "10.0.0.1" in body
    assert "WAF 룰과 입력값 검증을 우선 점검합니다." in body


def test_dashboard_renders_report_download_links(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    markdown_file = tmp_path / "web_attack_detection_report_20260620_160000.md"
    txt_file = tmp_path / "web_attack_detection_result_20260620_160000.txt"
    csv_file = tmp_path / "web_attack_detection_findings_20260620_160000.csv"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 1,
                    "total_login_events": 0,
                    "total_findings": 0,
                    "suspicious_ip_count": 0,
                    "risk_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": [],
                    "request_count_by_ip": {},
                },
                "timeline": [],
                "findings": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    markdown_file.write_text("# report", encoding="utf-8")
    txt_file.write_text("report", encoding="utf-8")
    csv_file.write_text("rule_id,severity\nSQLI-001,HIGH\n", encoding="utf-8")

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "리포트 다운로드" in body
    assert "/reports/web_attack_detection_report_20260620_160000.json" in body
    assert "/reports/web_attack_detection_report_20260620_160000.md" in body
    assert "/reports/web_attack_detection_result_20260620_160000.txt" in body
    assert "/reports/web_attack_detection_findings_20260620_160000.csv" in body


def test_dashboard_renders_csv_preview(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    csv_file = tmp_path / "web_attack_detection_findings_20260620_160000.csv"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 2,
                    "total_login_events": 0,
                    "total_findings": 2,
                    "suspicious_ip_count": 2,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1", "10.0.0.2"],
                    "request_count_by_ip": {"10.0.0.1": 1, "10.0.0.2": 1},
                },
                "timeline": [],
                "findings": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    csv_file.write_text(
        "rule_id,severity,attack_type,ip\n"
        "SQLI-001,HIGH,SQL Injection,10.0.0.1\n"
        "XSS-001,MEDIUM,XSS,10.0.0.2\n",
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "CSV Preview" in body
    assert "rule_id" in body
    assert "SQLI-001" in body
    assert "XSS-001" in body


def test_report_download_route_serves_allowed_report_file(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text('{"ok": true}', encoding="utf-8")

    client = app_module.app.test_client()
    response = client.get(f"/reports/{report_file.name}")

    assert response.status_code == 200
    assert response.headers["Content-Disposition"].startswith("attachment;")
    assert response.get_data(as_text=True) == '{"ok": true}'


def test_report_download_route_rejects_unexpected_filename(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/reports/../app.py")

    assert response.status_code == 404


def test_dashboard_can_select_report_file(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    old_report_file = tmp_path / "web_attack_detection_report_20260620_150000.json"
    latest_report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"

    old_report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 15:00:00",
                },
                "summary": {
                    "total_requests": 6,
                    "total_login_events": 1,
                    "total_findings": 1,
                    "suspicious_ip_count": 1,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1"],
                    "request_count_by_ip": {"10.0.0.1": 6},
                },
                "timeline": [
                    {
                        "timestamp": "2026-06-20 15:00:00",
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                    },
                ],
                "findings": [
                    {
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                        "response": "입력값 검증을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    latest_report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 7,
                    "total_login_events": 1,
                    "total_findings": 1,
                    "suspicious_ip_count": 1,
                    "risk_counts": {"HIGH": 0, "MEDIUM": 1, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.2"],
                    "request_count_by_ip": {"10.0.0.2": 7},
                },
                "timeline": [
                    {
                        "timestamp": "2026-06-20 16:00:00",
                        "rule_id": "XSS-001",
                        "severity": "MEDIUM",
                        "attack_type": "XSS",
                        "ip": "10.0.0.2",
                        "path": "/search",
                        "evidence": "matched_pattern=<script",
                    },
                ],
                "findings": [
                    {
                        "rule_id": "XSS-001",
                        "severity": "MEDIUM",
                        "attack_type": "XSS",
                        "ip": "10.0.0.2",
                        "path": "/search",
                        "evidence": "matched_pattern=<script",
                        "response": "출력 인코딩을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={old_report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert f'<option value="{old_report_file.name}" selected>' in body
    assert "SQLI-001" in body
    assert "XSS-001" not in body


def test_dashboard_handles_invalid_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text("{invalid json", encoding="utf-8")

    client = app_module.app.test_client()
    response = client.get(f"/dashboard?report={report_file.name}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "JSON 리포트를 읽을 수 없습니다" in body
    assert report_file.name in body
    assert "탐지 결과가 없습니다." in body


def test_dashboard_filters_findings_by_query_parameters(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 10,
                    "total_login_events": 4,
                    "total_findings": 2,
                    "suspicious_ip_count": 2,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 1, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1", "10.0.0.2"],
                    "request_count_by_ip": {"10.0.0.1": 10, "10.0.0.2": 4},
                },
                "timeline": [
                    {
                        "timestamp": "2026-06-20 16:00:00",
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                    },
                    {
                        "timestamp": "2026-06-20 16:00:01",
                        "rule_id": "SCAN-002",
                        "severity": "MEDIUM",
                        "attack_type": "Repeated 404",
                        "ip": "10.0.0.2",
                        "path": "-",
                        "evidence": "status_404_count=5, threshold=5",
                    },
                ],
                "findings": [
                    {
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                        "response": "입력값 검증을 확인합니다.",
                    },
                    {
                        "rule_id": "SCAN-002",
                        "severity": "MEDIUM",
                        "attack_type": "Repeated 404",
                        "ip": "10.0.0.2",
                        "path": "-",
                        "evidence": "status_404_count=5, threshold=5",
                        "response": "스캔 행위 가능성을 확인합니다.",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(
        f"/dashboard?report={report_file.name}&severity=HIGH&attack_type=SQL%20Injection"
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "SQLI-001" in body
    assert "SCAN-002" not in body
    assert "2026-06-20 16:00:00" in body
    assert "2026-06-20 16:00:01" not in body
    assert '<option value="HIGH" selected>HIGH</option>' in body


def test_dashboard_renders_share_link_for_current_view(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)
    report_file = tmp_path / "web_attack_detection_report_20260620_160000.json"
    report_file.write_text(
        json.dumps(
            {
                "analysis_info": {
                    "analysis_time": "2026-06-20 16:00:00",
                },
                "summary": {
                    "total_requests": 10,
                    "total_login_events": 4,
                    "total_findings": 1,
                    "suspicious_ip_count": 1,
                    "risk_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                },
                "statistics": {
                    "suspicious_ips": ["10.0.0.1"],
                    "request_count_by_ip": {"10.0.0.1": 10},
                },
                "timeline": [
                    {
                        "timestamp": "2026-06-20 16:00:00",
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                    },
                ],
                "findings": [
                    {
                        "rule_id": "SQLI-001",
                        "severity": "HIGH",
                        "attack_type": "SQL Injection",
                        "ip": "10.0.0.1",
                        "path": "/login",
                        "evidence": "matched_pattern=' or",
                        "response": "입력값 검증을 확인합니다.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    client = app_module.app.test_client()
    response = client.get(
        f"/dashboard?report={report_file.name}&severity=HIGH&attack_type=SQL%20Injection&ip=10.0.0.1"
    )
    body = response.get_data(as_text=True)

    expected_path = (
        f"/dashboard?report={report_file.name}&amp;severity=HIGH"
        "&amp;attack_type=SQL+Injection&amp;ip=10.0.0.1"
    )

    assert response.status_code == 200
    assert "현재 보기 링크" in body
    assert expected_path in body
