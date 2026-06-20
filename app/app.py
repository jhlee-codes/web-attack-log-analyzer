from flask import Flask, abort, render_template, request, send_from_directory
from pathlib import Path
from collections import Counter
from urllib.parse import urlencode
import json
import logging
import re

app = Flask(__name__)

# 로그 저장 경로 설정
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
RESULT_DIR = PROJECT_ROOT / "result"

LOGIN_LOG_FILE = LOG_DIR / "login.log"
ACCESS_LOG_FILE = LOG_DIR / "access.log"
REPORT_FILE_PATTERN = re.compile(
    r"^web_attack_detection_(?:"
    r"report_\d{8}_\d{6}\.(?:json|md)|"
    r"result_\d{8}_\d{6}\.txt|"
    r"findings_\d{8}_\d{6}\.csv"
    r")$"
)

def setup_logger(logger_name, log_file):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)

    return logger


def get_json_reports():
    return sorted(RESULT_DIR.glob("web_attack_detection_report_*.json"), reverse=True)


def get_selected_json_report(report_name: str = ""):
    report_files = get_json_reports()

    if not report_files:
        return None

    if report_name:
        for report_file in report_files:
            if report_file.name == report_name:
                return report_file

    return report_files[0]


def build_report_downloads(report_file: Path | None) -> list[dict]:
    if report_file is None:
        return []

    timestamp = report_file.stem.removeprefix("web_attack_detection_report_")
    candidates = [
        ("JSON", RESULT_DIR / f"web_attack_detection_report_{timestamp}.json"),
        ("Markdown", RESULT_DIR / f"web_attack_detection_report_{timestamp}.md"),
        ("TXT", RESULT_DIR / f"web_attack_detection_result_{timestamp}.txt"),
        ("CSV", RESULT_DIR / f"web_attack_detection_findings_{timestamp}.csv"),
    ]

    return [
        {
            "label": label,
            "filename": candidate.name,
            "url": f"/reports/{candidate.name}",
        }
        for label, candidate in candidates
        if candidate.exists()
    ]


def parse_dashboard_filters(args):
    return {
        "severity": args.get("severity", "").strip(),
        "attack_type": args.get("attack_type", "").strip(),
        "ip": args.get("ip", "").strip(),
    }


def finding_matches_dashboard_filters(finding: dict, filters: dict) -> bool:
    if filters["severity"] and finding.get("severity") != filters["severity"]:
        return False

    if filters["attack_type"] and finding.get("attack_type") != filters["attack_type"]:
        return False

    if filters["ip"] and finding.get("ip") != filters["ip"]:
        return False

    return True


def timeline_matches_dashboard_filters(item: dict, filters: dict) -> bool:
    if filters["severity"] and item.get("severity") != filters["severity"]:
        return False

    if filters["attack_type"] and item.get("attack_type") != filters["attack_type"]:
        return False

    if filters["ip"] and item.get("ip") != filters["ip"]:
        return False

    return True


def build_dashboard_summary(base_summary: dict, findings: list[dict]) -> dict:
    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in risk_counts:
            risk_counts[severity] += 1

    return {
        "total_requests": base_summary.get("total_requests", 0),
        "total_login_events": base_summary.get("total_login_events", 0),
        "total_findings": len(findings),
        "suspicious_ip_count": len({item.get("ip") for item in findings if item.get("ip") != "-"}),
        "risk_counts": risk_counts,
    }


def build_filter_options(findings: list[dict]) -> dict:
    return {
        "severities": sorted({item.get("severity") for item in findings if item.get("severity")}),
        "attack_types": sorted({item.get("attack_type") for item in findings if item.get("attack_type")}),
        "ips": sorted({item.get("ip") for item in findings if item.get("ip") and item.get("ip") != "-"}),
    }


def build_dashboard_share_path(filters: dict, report_file: Path | None = None) -> str:
    query_params = {}

    if report_file is not None:
        query_params["report"] = report_file.name

    for key in ("severity", "attack_type", "ip"):
        if filters.get(key):
            query_params[key] = filters[key]

    if not query_params:
        return "/dashboard"

    return f"/dashboard?{urlencode(query_params)}"


def normalize_executive_summary(executive_summary: dict | None) -> dict:
    executive_summary = executive_summary or {}

    return {
        "overall_risk": executive_summary.get("overall_risk", "NONE"),
        "top_attack_type": executive_summary.get("top_attack_type", "-"),
        "top_suspicious_ip": executive_summary.get("top_suspicious_ip", "-"),
        "priority_action": executive_summary.get("priority_action", "-"),
    }


def build_empty_dashboard_data(
    filters: dict,
    report_files: list[Path] | None = None,
    report_file: Path | None = None,
    error: str = "",
) -> dict:
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    return {
        "report_file": report_file,
        "report_files": report_files or [],
        "downloads": build_report_downloads(report_file),
        "analysis_info": {},
        "summary": {
            "total_requests": 0,
            "total_login_events": 0,
            "total_findings": 0,
            "suspicious_ip_count": 0,
            "risk_counts": risk_counts,
        },
        "executive_summary": normalize_executive_summary(None),
        "statistics": {
            "suspicious_ips": [],
        },
        "risk_chart": build_count_chart(risk_counts),
        "attack_type_counts": {},
        "attack_type_chart": [],
        "top_request_ips": [],
        "filter_options": {"severities": [], "attack_types": [], "ips": []},
        "filters": filters,
        "share_path": build_dashboard_share_path(filters, report_file),
        "timeline": [],
        "recent_findings": [],
        "error": error,
    }


def load_dashboard_data(filters: dict | None = None, report_name: str = ""):
    filters = filters or {"severity": "", "attack_type": "", "ip": ""}
    report_files = get_json_reports()
    report_file = get_selected_json_report(report_name)

    if report_file is None:
        return build_empty_dashboard_data(filters)

    try:
        with report_file.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        return build_empty_dashboard_data(
            filters=filters,
            report_files=report_files,
            report_file=report_file,
            error=f"JSON 리포트를 읽을 수 없습니다: {error}",
        )

    all_findings = payload.get("findings", [])
    findings = [
        finding
        for finding in all_findings
        if finding_matches_dashboard_filters(finding, filters)
    ]
    attack_type_counts = Counter(item.get("attack_type", "Unknown") for item in findings)
    statistics = payload.get("statistics", {})
    summary = build_dashboard_summary(payload.get("summary", {}), findings)
    risk_counts = summary.get("risk_counts", {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
    request_count_by_ip = Counter(item.get("ip") for item in findings if item.get("ip") and item.get("ip") != "-")
    timeline = [
        item
        for item in payload.get("timeline", [])
        if timeline_matches_dashboard_filters(item, filters)
    ]

    return {
        "report_file": report_file,
        "report_files": report_files,
        "downloads": build_report_downloads(report_file),
        "analysis_info": payload.get("analysis_info", {}),
        "summary": summary,
        "executive_summary": normalize_executive_summary(payload.get("executive_summary")),
        "statistics": statistics,
        "risk_chart": build_count_chart(risk_counts),
        "attack_type_counts": dict(attack_type_counts.most_common()),
        "attack_type_chart": build_count_chart(dict(attack_type_counts.most_common())),
        "top_request_ips": build_count_chart(request_count_by_ip, limit=5),
        "filter_options": build_filter_options(all_findings),
        "filters": filters,
        "share_path": build_dashboard_share_path(filters, report_file),
        "timeline": timeline,
        "recent_findings": findings[-20:][::-1],
        "error": "",
    }


def build_count_chart(counts: dict, limit: int | None = None) -> list[dict]:
    sorted_items = sorted(counts.items(), key=lambda item: item[1], reverse=True)

    if limit is not None:
        sorted_items = sorted_items[:limit]

    max_count = max((count for _, count in sorted_items), default=0)

    return [
        {
            "label": label,
            "count": count,
            "percent": round((count / max_count) * 100) if max_count else 0,
        }
        for label, count in sorted_items
    ]


# 로그인 로그 설정
login_logger = setup_logger("login_logger", LOGIN_LOG_FILE)

# 전체 요청 로그 설정
access_logger = setup_logger("access_logger", ACCESS_LOG_FILE)


# 실습용 계정
VALID_ID = "admin"
VALID_PASSWORD = "password123"


@app.after_request
def log_access(response):
    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "-")
    query_string = request.query_string.decode("utf-8", errors="replace")

    access_logger.info(
        f'HTTP_REQUEST ip={client_ip} '
        f'method={request.method} '
        f'path="{request.path}" '
        f'query="{query_string}" '
        f'status={response.status_code} '
        f'user_agent="{user_agent}"'
    )

    return response


@app.route("/")
def index():
    return "web-attack-log-analyzer basic web server"


@app.route("/dashboard")
def dashboard():
    filters = parse_dashboard_filters(request.args)
    report_name = request.args.get("report", "").strip()
    return render_template("dashboard.html", dashboard=load_dashboard_data(filters, report_name))


@app.route("/reports/<path:filename>")
def download_report(filename):
    if not REPORT_FILE_PATTERN.fullmatch(filename):
        abort(404)

    report_file = RESULT_DIR / filename

    if not report_file.is_file():
        abort(404)

    return send_from_directory(RESULT_DIR, filename, as_attachment=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("id", "")
        password = request.form.get("password", "")

        client_ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "-")

        if user_id == VALID_ID and password == VALID_PASSWORD:
            login_logger.info(
                f'LOGIN_SUCCESS ip={client_ip} id={user_id} user_agent="{user_agent}"'
            )
            return "로그인 성공"

        login_logger.info(
            f'LOGIN_FAIL ip={client_ip} id={user_id} user_agent="{user_agent}"'
        )
        return "로그인 실패"

    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)         
