from flask import Flask, render_template, request
from pathlib import Path
import logging

app = Flask(__name__)

# 로그 저장 경로 설정
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "login.log"

# 로그인 로그 설정
login_logger = logging.getLogger("login_logger")
login_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
formatter = logging.Formatter(
    "%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)

if not login_logger.handlers:
    login_logger.addHandler(file_handler)

# 실습용 계정
VALID_ID = "admin"
VALID_PASSWORD = "password123"

@app.route("/")
def index():
    return "web-attack-log-analyzer basic web server"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        id = request.form.get("id", "")
        password = request.form.get("password", "")

        client_ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "-")

        if id == VALID_ID and password == VALID_PASSWORD:
            login_logger.info(
                f"LOGIN_SUCCESS ip={client_ip} id={id} user_agent=\"{user_agent}\""
            )
            return "로그인 성공"

        login_logger.info(
            f"LOGIN_FAIL ip={client_ip} id={id} user_agent=\"{user_agent}\""
        )
        return "로그인 실패"

    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)