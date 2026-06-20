from flask import Flask, render_template, request
from pathlib import Path
from collections import Counter
import json
import logging

app = Flask(__name__)

# 로그 저장 경로 설정
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
RESULT_DIR = PROJECT_ROOT / "result"

LOGIN_LOG_FILE = LOG_DIR / "login.log"
ACCESS_LOG_FILE = LOG_DIR / "access.log"

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


def get_latest_json_report():
    report_files = sorted(RESULT_DIR.glob("web_attack_detection_report_*.json"))

    if not report_files:
        return None

    return report_files[-1]


def load_dashboard_data():
    report_file = get_latest_json_report()

    if report_file is None:
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        return {
            "report_file": None,
            "analysis_info": {},
            "summary": {
                "total_requests": 0,
                "total_login_events": 0,
                "total_findings": 0,
                "suspicious_ip_count": 0,
                "risk_counts": risk_counts,
            },
            "statistics": {
                "suspicious_ips": [],
            },
            "risk_chart": build_count_chart(risk_counts),
            "attack_type_counts": {},
            "attack_type_chart": [],
            "top_request_ips": [],
            "recent_findings": [],
        }

    with report_file.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    findings = payload.get("findings", [])
    attack_type_counts = Counter(item.get("attack_type", "Unknown") for item in findings)
    statistics = payload.get("statistics", {})
    summary = payload.get("summary", {})
    risk_counts = summary.get("risk_counts", {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
    request_count_by_ip = statistics.get("request_count_by_ip", {})

    return {
        "report_file": report_file,
        "analysis_info": payload.get("analysis_info", {}),
        "summary": summary,
        "statistics": statistics,
        "risk_chart": build_count_chart(risk_counts),
        "attack_type_counts": dict(attack_type_counts.most_common()),
        "attack_type_chart": build_count_chart(dict(attack_type_counts.most_common())),
        "top_request_ips": build_count_chart(request_count_by_ip, limit=5),
        "recent_findings": findings[-20:][::-1],
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
    return render_template("dashboard.html", dashboard=load_dashboard_data())


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
