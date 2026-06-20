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
    assert '<option value="HIGH" selected>HIGH</option>' in body
