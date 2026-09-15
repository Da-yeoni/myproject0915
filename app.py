import getpass
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import time
from datetime import timedelta

from flask import (
    Flask,
    abort,
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

# [보안] 세션 서명 키.
# Flask 세션 쿠키는 '암호화'가 아니라 '서명'만 된다. 키가 노출되면 공격자가
# is_admin/user_id 를 담은 세션 쿠키를 위조해 관리자로 로그인할 수 있다.
# 절대 코드에 하드코딩/커밋하지 말 것. 환경변수로 주고, 없으면 매 실행마다
# 랜덤 생성한다(재시작 시 세션 초기화 = 위조 불가).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# [보안] 세션 쿠키 하드닝
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JS(document.cookie)로 세션 접근 차단 (XSS 완화)
    SESSION_COOKIE_SAMESITE="Lax",     # CSRF 완화
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # HTTPS 배포 시 1
    PERMANENT_SESSION_LIFETIME=timedelta(hours=6),
    MAX_CONTENT_LENGTH=64 * 1024,      # 요청 본문 64KB 제한 (대용량 페이로드 DoS 차단)
)


@app.after_request
def set_security_headers(resp):
    """[보안] 방어 심층화용 응답 헤더."""
    # 스크립트 실행 자체를 차단 -> 설령 XSS 가 있어도 flag 유출(exfil) 불가.
    # 이 앱은 JS/외부 리소스를 전혀 쓰지 않으므로 매우 엄격하게 걸어도 무방.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memo.db")

# 초기 관리자 계정 정보
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# [보안] 관리자 비밀번호 결정. 우선순위:
#   1) 환경변수 ADMIN_PASSWORD
#   2) 없고 대화형 터미널이면 getpass 로 직접 입력 (화면에 안 찍히고 기록도 안 남음)
#   3) 둘 다 없으면 admin 계정을 만들지 않음 => 아무도 로그인 못 함
# 소스/DB/로그/쉘히스토리 어디에도 평문 비번이 남지 않는다.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD and sys.stdin.isatty():
    ADMIN_PASSWORD = getpass.getpass("[관리자 비밀번호 입력] ") or None

# 관리자 계정에 미리 심어둘 비밀 메모(flag). 결정 우선순위는 비밀번호와 동일:
#   1) 환경변수 ADMIN_MEMO
#   2) 없고 대화형 터미널이면 직접 입력 (기록 안 남음)
#   3) 둘 다 없으면 flag 메모를 시딩하지 않음
# 소스코드엔 flag 를 절대 두지 않는다.
ADMIN_MEMO = os.environ.get("ADMIN_MEMO")
if not ADMIN_MEMO and sys.stdin.isatty():
    ADMIN_MEMO = getpass.getpass("[관리자 메모(flag) 입력, 없으면 Enter] ") or None

# [보안] 로그인 무차별 대입 완화 (프로세스 메모리 기준, 시간창 방식)
MAX_LOGIN_ATTEMPTS = 10          # 창(window) 내 허용 실패 횟수
LOGIN_WINDOW = 300               # 창 길이(초). 초과 시 카운터 리셋
FAIL_DELAY = 0.4                 # 실패 시 인위적 지연(초) -> brute-force 비용 증가
_login_attempts = {}             # ip -> (count, first_ts)

# [보안] 계정 존재 여부를 타이밍으로 유추(user enumeration)하지 못하도록,
# 존재하지 않는 계정에도 동일한 해시 검증 비용을 치르게 하는 더미 해시.
_DUMMY_HASH = generate_password_hash("this_is_a_dummy_password_for_timing")


def _fingerprint():
    """[보안] User-Agent 기반 세션 지문. 쿠키를 탈취해도 다른 클라이언트에서
    재사용하면 지문이 달라져 무효화된다(secret_key 로 키드된 HMAC)."""
    ua = request.headers.get("User-Agent", "")
    return hmac.new(app.secret_key.encode(), ua.encode(), hashlib.sha256).hexdigest()


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
    """앱 시작 시 테이블을 생성하고 초기 관리자 데이터를 시딩한다."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS memos (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            content    TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )

    # 예전 스키마(is_admin 컬럼 없음)로 만들어진 DB를 위한 마이그레이션
    columns = [row["name"] for row in db.execute("PRAGMA table_info(users)")]
    if "is_admin" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

    # [보안] admin 계정은 ADMIN_PASSWORD 가 주어졌을 때만 존재한다.
    if ADMIN_PASSWORD:
        pw_hash = generate_password_hash(ADMIN_PASSWORD)
        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)
        ).fetchone()
        if admin is None:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                (ADMIN_USERNAME, pw_hash),
            )
            admin_id = cur.lastrowid
        else:
            admin_id = admin["id"]
            # env 비밀번호를 단일 진실로: 매 시작 시 비번/권한을 동기화한다.
            db.execute(
                "UPDATE users SET is_admin = 1, password_hash = ? WHERE id = ?",
                (pw_hash, admin_id),
            )

        # 관리자 비밀 메모(flag) 시딩. ADMIN_MEMO 가 있을 때만 심는다.
        if ADMIN_MEMO:
            exists = db.execute(
                "SELECT 1 FROM memos WHERE user_id = ? AND content = ?",
                (admin_id, ADMIN_MEMO),
            ).fetchone()
            if exists is None:
                db.execute(
                    "INSERT INTO memos (user_id, content) VALUES (?, ?)",
                    (admin_id, ADMIN_MEMO),
                )
    else:
        # 비밀번호가 없으면 admin 이 로그인하지 못하도록 계정을 비활성 상태로 둔다.
        # (혹시 남아있는 admin 계정이 있으면 관리자 권한을 회수한다.)
        db.execute(
            "UPDATE users SET is_admin = 0 WHERE username = ?", (ADMIN_USERNAME,)
        )

    db.commit()
    db.close()


def current_user():
    """세션에 저장된 사용자 정보를 반환한다. 없으면 None."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    # [보안] 세션 지문 검증: 쿠키가 탈취돼 다른 클라이언트에서 재생되면 무효화.
    if not hmac.compare_digest(session.get("fp", ""), _fingerprint()):
        session.clear()
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def get_owned_memo(memo_id, user):
    """[보안] 메모를 소유자 검증과 함께 조회한다.
    내 메모가 아니면 존재 자체를 숨기기 위해 404 로 처리(IDOR 차단)."""
    memo = get_db().execute(
        "SELECT * FROM memos WHERE id = ?", (memo_id,)
    ).fetchone()
    if memo is None or memo["user_id"] != user["id"]:
        abort(404)
    return memo


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
<p>로그인이 유지되고 있습니다.</p>
<p><small>가입일: {{ user['created_at'] }}</small></p>
<hr>
<h3>&#128203; 내 메모</h3>
<p>
  <a href="{{ url_for('memo_new') }}">
    <button type="button">&#10133; 새 메모 작성</button>
  </a>
</p>
{% if memos %}
  <table width="100%" cellpadding="6" border="1">
    <tr><th width="50">번호</th><th>내용</th><th width="120">작성일</th><th width="60">보기</th></tr>
    {% for m in memos %}
      <tr>
        <td align="center">{{ m['id'] }}</td>
        {# 관리자(=flag 보유자)의 메모는 흰 글씨로 표시해 눈에 잘 안 띄게 함.
           일반 사용자 메모는 정상 표시. (드래그/소스보기 시엔 보임 - 눈속임용) #}
        <td>{% if user['is_admin'] %}<font color="white">{{ m['content'] | truncate(40, True) }}</font>{% else %}{{ m['content'] | truncate(40, True) }}{% endif %}</td>
        <td><small>{{ m['created_at'] }}</small></td>
        <td align="center"><a href="{{ url_for('memo_detail', memo_id=m['id']) }}">보기</a></td>
      </tr>
    {% endfor %}
  </table>
{% else %}
  <p><i>아직 작성한 메모가 없습니다.</i></p>
{% endif %}
<hr>
{% if user['is_admin'] %}
  <p>
    <a href="{{ url_for('admin') }}">
      <button type="button">&#128273; 관리자 페이지</button>
    </a>
  </p>
{% endif %}
<form method="post" action="{{ url_for('logout') }}">
  <button type="submit">&#128682; 로그아웃</button>
</form>
"""

ADMIN = """
<h2>&#128273; 관리자 페이지</h2>
<p>전체 회원 목록입니다. (관리자만 접근 가능)</p>
<table width="100%" cellpadding="6" border="1">
  <tr>
    <th width="50">ID</th><th>아이디</th><th width="70">관리자</th><th width="150">가입일</th>
  </tr>
  {% for u in users %}
    <tr>
      <td align="center">{{ u['id'] }}</td>
      <td>{{ u['username'] }}</td>
      <td align="center">{{ '&#9989;' | safe if u['is_admin'] else '-' }}</td>
      <td><small>{{ u['created_at'] }}</small></td>
    </tr>
  {% endfor %}
</table>
<p><small>총 {{ users | length }}명</small></p>
<hr>
<p><a href="{{ url_for('home') }}">&#8592; 홈으로</a></p>
"""

# 새 메모 작성 / 수정 공용 폼
MEMO_FORM = """
<h2>{{ '&#9999; 메모 수정' | safe if memo else '&#10133; 새 메모 작성' | safe }}</h2>
<form method="post" action="{{ action }}">
  <p>
    <textarea name="content" rows="8" cols="42" required autofocus>{{ memo['content'] if memo else '' }}</textarea>
  </p>
  <p>
    <button type="submit">&#128190; 저장</button>
    <a href="{{ url_for('home') }}"><button type="button">취소</button></a>
  </p>
</form>
"""

# 메모 상세 조회
MEMO_DETAIL = """
<h2>&#128203; 메모 상세</h2>
<p><small>번호 {{ memo['id'] }} · 작성일 {{ memo['created_at'] }}</small></p>
<hr>
<pre>{% if user['is_admin'] %}<font color="white">{{ memo['content'] }}</font>{% else %}{{ memo['content'] }}{% endif %}</pre>
<hr>
<p>
  <a href="{{ url_for('memo_edit', memo_id=memo['id']) }}">
    <button type="button">&#9999; 수정</button>
  </a>
</p>
<form method="post" action="{{ url_for('memo_delete', memo_id=memo['id']) }}">
  <button type="submit">&#128465; 삭제</button>
</form>
<hr>
<p><a href="{{ url_for('home') }}">&#8592; 목록으로</a></p>
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
    memos = get_db().execute(
        "SELECT * FROM memos WHERE user_id = ? ORDER BY id DESC", (user["id"],)
    ).fetchall()
    return page("홈", HOME, user=user, memos=memos)


@app.route("/memo/new", methods=["GET", "POST"])
def memo_new():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("메모 내용을 입력해 주세요.")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO memos (user_id, content) VALUES (?, ?)",
                (user["id"], content),
            )
            db.commit()
            flash("메모가 작성되었습니다.")
            return redirect(url_for("home"))

    return page("새 메모", MEMO_FORM, user=user, memo=None, action=url_for("memo_new"))


@app.route("/memo/<int:memo_id>")
def memo_detail(memo_id):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    memo = get_owned_memo(memo_id, user)  # 소유자 검증 (남의 메모면 404)
    return page("메모 상세", MEMO_DETAIL, user=user, memo=memo)


@app.route("/memo/<int:memo_id>/edit", methods=["GET", "POST"])
def memo_edit(memo_id):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    memo = get_owned_memo(memo_id, user)  # 소유자 검증

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("메모 내용을 입력해 주세요.")
        else:
            db = get_db()
            db.execute(
                "UPDATE memos SET content = ? WHERE id = ?", (content, memo_id)
            )
            db.commit()
            flash("메모가 수정되었습니다.")
            return redirect(url_for("memo_detail", memo_id=memo_id))

    return page(
        "메모 수정", MEMO_FORM, user=user, memo=memo,
        action=url_for("memo_edit", memo_id=memo_id),
    )


@app.route("/memo/<int:memo_id>/delete", methods=["POST"])
def memo_delete(memo_id):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    get_owned_memo(memo_id, user)  # 소유자 검증 (남의 메모면 404)
    db = get_db()
    db.execute("DELETE FROM memos WHERE id = ?", (memo_id,))
    db.commit()
    flash("메모가 삭제되었습니다.")
    return redirect(url_for("home"))


@app.route("/admin")
def admin():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    # 관리자 권한이 없으면 접근 차단
    if not user["is_admin"]:
        flash("관리자만 접근할 수 있는 페이지입니다.")
        return redirect(url_for("home"))
    users = get_db().execute(
        "SELECT * FROM users ORDER BY id"
    ).fetchall()
    return page("관리자", ADMIN, user=user, users=users)


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
        ip = request.remote_addr or "?"
        now = time.time()

        # [보안] 시간창 기반 무차별 대입 제한
        count, first_ts = _login_attempts.get(ip, (0, now))
        if now - first_ts > LOGIN_WINDOW:          # 창이 지났으면 리셋
            count, first_ts = 0, now
        if count >= MAX_LOGIN_ATTEMPTS:
            flash("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.")
            return page("로그인", LOGIN)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # [보안] 계정 존재 여부와 무관하게 항상 해시 검증을 수행(타이밍 균일화).
        if user is None:
            check_password_hash(_DUMMY_HASH, password)
            ok = False
        else:
            ok = check_password_hash(user["password_hash"], password)

        if not ok:
            _login_attempts[ip] = (count + 1, first_ts)
            time.sleep(FAIL_DELAY)                  # 실패 지연으로 대입 비용 증가
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            _login_attempts.pop(ip, None)           # 성공 시 카운터 초기화
            session.clear()
            session["user_id"] = user["id"]
            session["fp"] = _fingerprint()          # 세션 지문 고정
            session.permanent = True                # 로그인 세션 유지
            return redirect(url_for("home"))

    return page("로그인", LOGIN)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 앱 실행
# ---------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
   
    app.run(host="0.0.0.0", port=8000)
