from flask import Flask, render_template, request
from pathlib import Path
import logging

app = Flask(__name__)

# 로그 저장 경로 설정
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

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