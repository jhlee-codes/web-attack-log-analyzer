from flask import Flask, abort, redirect, render_template, request, send_from_directory, url_for
from pathlib import Path
from collections import Counter
from datetime import datetime
from tempfile import TemporaryDirectory
from urllib.parse import urlencode
import csv
import json
import logging
import re
import sys

app = Flask(__name__)

# 로그 저장 경로 설정
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzer import web_log_analyzer

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
RESULT_DIR = PROJECT_ROOT / "result"
RULES_FILE = PROJECT_ROOT / "analyzer" / "rules.json"

LOGIN_LOG_FILE = LOG_DIR / "login.log"
ACCESS_LOG_FILE = LOG_DIR / "access.log"
REPORT_FILE_PATTERN = re.compile(
    r"^web_attack_detection_(?:"
    r"report_\d{8}_\d{6}\.(?:json|md)|"
    r"result_\d{8}_\d{6}\.txt|"
    r"findings_\d{8}_\d{6}\.csv"
    r")$"
)
FINDING_PREVIEW_FIELDS = [
    "rule_id",
    "severity",
    "attack_type",
    "timestamp",
    "ip",
    "method",
    "path",
    "status",
    "evidence",
]

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


def get_findings_csv_file(report_file: Path | None) -> Path | None:
    if report_file is None:
        return None

    timestamp = report_file.stem.removeprefix("web_attack_detection_report_")
    return RESULT_DIR / f"web_attack_detection_findings_{timestamp}.csv"


def get_related_report_files(report_file: Path) -> list[Path]:
    timestamp = report_file.stem.removeprefix("web_attack_detection_report_")

    return [
        RESULT_DIR / f"web_attack_detection_report_{timestamp}.json",
        RESULT_DIR / f"web_attack_detection_report_{timestamp}.md",
        RESULT_DIR / f"web_attack_detection_result_{timestamp}.txt",
        RESULT_DIR / f"web_attack_detection_findings_{timestamp}.csv",
    ]


def delete_report_bundle(filename: str):
    if not REPORT_FILE_PATTERN.fullmatch(filename):
        abort(404)

    report_file = RESULT_DIR / filename

    if not report_file.is_file() or not filename.startswith("web_attack_detection_report_") or not filename.endswith(".json"):
        abort(404)

    for related_file in get_related_report_files(report_file):
        if related_file.exists():
            related_file.unlink()


def build_findings_preview(findings: list[dict], limit: int = 20) -> dict:
    return {
        "filename": "",
        "headers": FINDING_PREVIEW_FIELDS,
        "rows": [
            {field: finding.get(field, "-") for field in FINDING_PREVIEW_FIELDS}
            for finding in findings[:limit]
        ],
        "error": "",
    }


def build_csv_preview(report_file: Path | None, fallback_findings: list[dict] | None = None, limit: int = 20) -> dict:
    csv_file = get_findings_csv_file(report_file)

    if csv_file is None or not csv_file.exists():
        if fallback_findings:
            return build_findings_preview(fallback_findings, limit)

        return {
            "filename": "",
            "headers": [],
            "rows": [],
            "error": "",
        }

    try:
        with csv_file.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            headers = reader.fieldnames or []
            rows = [
                {header: row.get(header, "") for header in headers}
                for _, row in zip(range(limit), reader)
            ]
    except (OSError, csv.Error) as error:
        return {
            "filename": csv_file.name,
            "headers": [],
            "rows": [],
            "error": f"CSV 미리보기를 읽을 수 없습니다: {error}",
        }

    return {
        "filename": csv_file.name,
        "headers": headers,
        "rows": rows,
        "error": "",
    }


def build_report_history() -> list[dict]:
    history = []

    for report_file in get_json_reports():
        row = {
            "filename": report_file.name,
            "analysis_time": "-",
            "overall_risk": "ERROR",
            "total_findings": "-",
            "suspicious_ip_count": "-",
            "dashboard_url": url_for("dashboard", report=report_file.name),
            "downloads": build_report_downloads(report_file),
            "error": "",
        }

        try:
            with report_file.open("r", encoding="utf-8") as file:
                payload = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            row["error"] = f"JSON 리포트를 읽을 수 없습니다: {error}"
        else:
            summary = payload.get("summary", {})
            executive_summary = normalize_executive_summary(payload.get("executive_summary"))
            row["analysis_time"] = payload.get("analysis_info", {}).get("analysis_time", "-")
            row["overall_risk"] = executive_summary["overall_risk"]
            row["total_findings"] = summary.get("total_findings", 0)
            row["suspicious_ip_count"] = summary.get("suspicious_ip_count", 0)

        history.append(row)

    return history


def load_detection_rules_for_view() -> dict:
    try:
        with RULES_FILE.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        return {
            "rules_file": RULES_FILE,
            "rules": [],
            "error": f"탐지 룰 파일을 읽을 수 없습니다: {error}",
        }

    rules = payload.get("rules", [])

    if not isinstance(rules, list):
        return {
            "rules_file": RULES_FILE,
            "rules": [],
            "error": "탐지 룰 파일 형식이 올바르지 않습니다: rules는 list여야 합니다.",
        }

    return {
        "rules_file": RULES_FILE,
        "rules": rules,
        "error": "",
    }


def parse_rule_filters(args) -> dict:
    return {
        "q": args.get("q", "").strip(),
        "severity": args.get("severity", "").strip(),
        "match_type": args.get("match_type", "").strip(),
    }


def rule_matches_filters(rule: dict, filters: dict) -> bool:
    if filters["severity"] and rule.get("severity") != filters["severity"]:
        return False

    if filters["match_type"] and rule.get("match_type", "contains") != filters["match_type"]:
        return False

    if filters["q"]:
        search_text = " ".join(
            [
                str(rule.get("rule_id", "")),
                str(rule.get("attack_type", "")),
                str(rule.get("description", "")),
                " ".join(str(pattern) for pattern in rule.get("patterns", [])),
            ]
        ).lower()

        if filters["q"].lower() not in search_text:
            return False

    return True


def apply_rule_filters(rules: list[dict], filters: dict) -> list[dict]:
    return [rule for rule in rules if rule_matches_filters(rule, filters)]


def build_rule_filter_options(rules: list[dict]) -> dict:
    return {
        "severities": sorted({rule.get("severity") for rule in rules if rule.get("severity")}),
        "match_types": sorted({rule.get("match_type", "contains") for rule in rules}),
    }


def build_rules_view(filters: dict) -> dict:
    rules_view = load_detection_rules_for_view()
    all_rules = rules_view["rules"]

    rules_view["filter_options"] = build_rule_filter_options(all_rules)
    rules_view["filters"] = filters
    rules_view["total_count"] = len(all_rules)
    rules_view["rules"] = apply_rule_filters(all_rules, filters)

    return rules_view


def has_uploaded_file(file_storage) -> bool:
    return bool(file_storage and file_storage.filename)


def parse_upload_threshold(value: str) -> int:
    try:
        threshold = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("반복 탐지 기준은 1 이상의 숫자여야 합니다.") from error

    if threshold < 1:
        raise ValueError("반복 탐지 기준은 1 이상의 숫자여야 합니다.")

    return threshold


def save_uploaded_file_or_empty(file_storage, destination: Path):
    if has_uploaded_file(file_storage):
        file_storage.save(destination)
        return

    destination.write_text("", encoding="utf-8")


def generate_reports_from_logs(access_log: Path, login_log: Path, access_format: str, threshold: int) -> str:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    rules = web_log_analyzer.load_detection_rules(RULES_FILE)
    access_analysis = web_log_analyzer.analyze_access_log(
        access_log=access_log,
        threshold=threshold,
        rules=rules,
        access_format=access_format,
    )
    login_analysis = web_log_analyzer.analyze_login_log(login_log, threshold)
    filters = {
        "severities": set(),
        "attack_types": set(),
        "ips": set(),
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = RESULT_DIR / f"web_attack_detection_result_{timestamp}.txt"
    markdown_file = RESULT_DIR / f"web_attack_detection_report_{timestamp}.md"
    json_file = RESULT_DIR / f"web_attack_detection_report_{timestamp}.json"
    csv_file = RESULT_DIR / f"web_attack_detection_findings_{timestamp}.csv"

    web_log_analyzer.write_txt_report(
        result_file=result_file,
        access_log=access_log,
        login_log=login_log,
        rules_file=RULES_FILE,
        access_format=access_format,
        filters=filters,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )
    web_log_analyzer.write_markdown_report(
        markdown_file=markdown_file,
        access_log=access_log,
        login_log=login_log,
        rules_file=RULES_FILE,
        rules=rules,
        access_format=access_format,
        filters=filters,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )
    web_log_analyzer.write_json_report(
        json_file=json_file,
        access_log=access_log,
        login_log=login_log,
        rules_file=RULES_FILE,
        access_format=access_format,
        filters=filters,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )
    web_log_analyzer.write_csv_report(
        csv_file=csv_file,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )

    return json_file.name


def build_live_report_payload() -> dict:
    rules = web_log_analyzer.load_detection_rules(RULES_FILE)
    access_analysis = web_log_analyzer.analyze_access_log(
        access_log=ACCESS_LOG_FILE,
        threshold=web_log_analyzer.DEFAULT_THRESHOLD,
        rules=rules,
        access_format="custom",
    )
    login_analysis = web_log_analyzer.analyze_login_log(LOGIN_LOG_FILE, web_log_analyzer.DEFAULT_THRESHOLD)

    return web_log_analyzer.build_report_payload(
        access_log=ACCESS_LOG_FILE,
        login_log=LOGIN_LOG_FILE,
        rules_file=RULES_FILE,
        access_format="custom",
        filters={
            "severities": set(),
            "attack_types": set(),
            "ips": set(),
        },
        threshold=web_log_analyzer.DEFAULT_THRESHOLD,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )


def analyze_uploaded_logs(access_file, login_file, access_format: str, threshold: int) -> str:
    with TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        access_log = temp_path / "uploaded_access.log"
        login_log = temp_path / "uploaded_login.log"

        save_uploaded_file_or_empty(access_file, access_log)
        save_uploaded_file_or_empty(login_file, login_log)

        return generate_reports_from_logs(access_log, login_log, access_format, threshold)


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
    mode: str = "live",
    error: str = "",
) -> dict:
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    return {
        "report_file": report_file,
        "report_files": report_files or [],
        "mode": mode,
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
        "csv_preview": build_csv_preview(report_file),
        "error": error,
    }


def build_dashboard_data_from_payload(
    payload: dict,
    filters: dict,
    report_files: list[Path],
    report_file: Path | None,
    mode: str,
    error: str = "",
) -> dict:
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
        "mode": mode,
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
        "csv_preview": build_csv_preview(report_file, fallback_findings=findings if mode == "live" else None),
        "error": error,
    }


def load_dashboard_data(filters: dict | None = None, report_name: str = ""):
    filters = filters or {"severity": "", "attack_type": "", "ip": ""}
    external_error = request.args.get("error", "").strip()
    report_files = get_json_reports()

    if report_name:
        report_file = get_selected_json_report(report_name)

        if report_file is None:
            return build_empty_dashboard_data(filters, report_files=report_files, mode="saved", error=external_error)

        try:
            with report_file.open("r", encoding="utf-8") as file:
                payload = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            return build_empty_dashboard_data(
                filters=filters,
                report_files=report_files,
                report_file=report_file,
                mode="saved",
                error=f"JSON 리포트를 읽을 수 없습니다: {error}",
            )

        return build_dashboard_data_from_payload(
            payload=payload,
            filters=filters,
            report_files=report_files,
            report_file=report_file,
            mode="saved",
            error=external_error,
        )

    try:
        payload = build_live_report_payload()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return build_empty_dashboard_data(
            filters=filters,
            report_files=report_files,
            mode="live",
            error=str(error),
        )

    return build_dashboard_data_from_payload(
        payload=payload,
        filters=filters,
        report_files=report_files,
        report_file=None,
        mode="live",
        error=external_error,
    )


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


@app.route("/rules")
def rules():
    return render_template("rules.html", rules_view=build_rules_view(parse_rule_filters(request.args)))


@app.route("/reports")
def reports():
    return render_template("reports.html", reports=build_report_history())


@app.route("/reports/delete", methods=["POST"])
def delete_report():
    delete_report_bundle(request.form.get("filename", "").strip())
    return redirect(url_for("reports"))


@app.route("/reports/generate", methods=["POST"])
def generate_report():
    try:
        report_name = generate_reports_from_logs(
            access_log=ACCESS_LOG_FILE,
            login_log=LOGIN_LOG_FILE,
            access_format="custom",
            threshold=web_log_analyzer.DEFAULT_THRESHOLD,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return redirect(url_for("dashboard", error=str(error)))

    return redirect(url_for("dashboard", report=report_name))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    upload_view = {
        "error": "",
        "access_formats": sorted(web_log_analyzer.SUPPORTED_ACCESS_FORMATS),
        "selected_access_format": "custom",
        "threshold": web_log_analyzer.DEFAULT_THRESHOLD,
    }

    if request.method == "POST":
        access_file = request.files.get("access_log")
        login_file = request.files.get("login_log")
        access_format = request.form.get("access_format", "custom").strip()
        upload_view["selected_access_format"] = access_format
        upload_view["threshold"] = request.form.get("threshold", str(web_log_analyzer.DEFAULT_THRESHOLD)).strip()

        try:
            if access_format not in web_log_analyzer.SUPPORTED_ACCESS_FORMATS:
                raise ValueError("지원하지 않는 Access 로그 포맷입니다.")

            if not has_uploaded_file(access_file) and not has_uploaded_file(login_file):
                raise ValueError("Access 로그 또는 Login 로그 중 하나 이상을 업로드해야 합니다.")

            threshold = parse_upload_threshold(upload_view["threshold"])
            report_name = analyze_uploaded_logs(access_file, login_file, access_format, threshold)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            upload_view["error"] = str(error)
        else:
            return redirect(url_for("dashboard", report=report_name))

    return render_template("upload.html", upload_view=upload_view)


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
