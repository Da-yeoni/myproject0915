import os
import sqlite3

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memo.db")


# ---------------------------------------------------------------------------
# 데이터베이스 헬퍼
# ---------------------------------------------------------------------------
def get_db():
    """요청 단위로 재사용되는 DB 커넥션을 반환한다."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """앱 시작 시 users 테이블을 생성한다."""
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    db.close()


def current_user():
    """세션에 저장된 사용자 정보를 반환한다. 없으면 None."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


# ---------------------------------------------------------------------------
# HTML 템플릿 (CSS 없이 순수 HTML 태그로만 구성)
# ---------------------------------------------------------------------------
BASE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모 서비스</title>
</head>
<body>
  <center>
    <table width="420" cellpadding="10">
      <tr>
        <td>
          <h1>&#128221; 메모 서비스</h1>
          <hr>
          {% with messages = get_flashed_messages() %}
            {% if messages %}
              <blockquote>
                {% for m in messages %}
                  <b>&#9888; {{ m }}</b><br>
                {% endfor %}
              </blockquote>
            {% endif %}
          {% endwith %}
          {{ body | safe }}
        </td>
      </tr>
    </table>
  </center>
</body>
</html>
"""

HOME = """
<h2>{{ user['username'] }}님, 환영합니다! &#128075;</h2>
<p>로그인이 유지되고 있습니다. 이제 메모 기능을 이용할 수 있습니다.</p>
<p><small>가입일: {{ user['created_at'] }}</small></p>
<hr>
<p>
  <a href="{{ url_for('logout') }}">
    <button type="button">&#128682; 로그아웃</button>
  </a>
</p>
"""

LOGIN = """
<h2>로그인</h2>
<form method="post" action="{{ url_for('login') }}">
  <table cellpadding="6">
    <tr>
      <td align="right"><label for="username">아이디</label></td>
      <td><input type="text" id="username" name="username" size="24" required autofocus></td>
    </tr>
    <tr>
      <td align="right"><label for="password">비밀번호</label></td>
      <td><input type="password" id="password" name="password" size="24" required></td>
    </tr>
    <tr>
      <td></td>
      <td><button type="submit">&#128273; 로그인</button></td>
    </tr>
  </table>
</form>
<hr>
<p>계정이 없으신가요? <a href="{{ url_for('register') }}">회원가입</a></p>
"""

REGISTER = """
<h2>회원가입</h2>
<form method="post" action="{{ url_for('register') }}">
  <table cellpadding="6">
    <tr>
      <td align="right"><label for="username">아이디</label></td>
      <td><input type="text" id="username" name="username" size="24" required autofocus></td>
    </tr>
    <tr>
      <td align="right"><label for="password">비밀번호</label></td>
      <td><input type="password" id="password" name="password" size="24" required></td>
    </tr>
    <tr>
      <td align="right"><label for="password2">비밀번호 확인</label></td>
      <td><input type="password" id="password2" name="password2" size="24" required></td>
    </tr>
    <tr>
      <td></td>
      <td><button type="submit">&#9989; 가입하기</button></td>
    </tr>
  </table>
</form>
<hr>
<p>이미 계정이 있으신가요? <a href="{{ url_for('login') }}">로그인</a></p>
"""


def page(title, body_template, **context):
    """공통 레이아웃(BASE) 안에 개별 페이지 본문을 렌더링한다."""
    body = render_template_string(body_template, **context)
    return render_template_string(BASE, title=title, body=body)


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    return page("홈", HOME, user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해 주세요.")
        elif password != password2:
            flash("비밀번호가 서로 일치하지 않습니다.")
        else:
            db = get_db()
            exists = db.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if exists:
                flash("이미 사용 중인 아이디입니다.")
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                flash("회원가입이 완료되었습니다. 로그인해 주세요.")
                return redirect(url_for("login"))

    return page("회원가입", REGISTER)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True  # 로그인 세션 유지
            return redirect(url_for("home"))

    return page("로그인", LOGIN)


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 앱 실행
# ---------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    app.run(debug=True)
