import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import app as app_module


def test_dashboard_renders_without_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "RESULT_DIR", tmp_path)
    monkeypatch.setattr(app_module.access_logger, "info", lambda message: None)

    client = app_module.app.test_client()
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "JSON 리포트 없음" in response.get_data(as_text=True)


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
    response = client.get("/dashboard")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "web_attack_detection_report_20260620_160000.json" in body
    assert "SQLI-001" in body
    assert "10.0.0.1" in body
    assert "요청 IP Top 5" in body
    assert "Repeated 404" in body
    assert "Timeline" in body
    assert "2026-06-20 16:00:00" in body


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
    response = client.get("/dashboard")
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
    response = client.get("/dashboard?severity=HIGH&attack_type=SQL%20Injection")
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
