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
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
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

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            body       TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
# 스타일시트
# ---------------------------------------------------------------------------
# [보안] CSP 가 default-src 'self' 이므로 인라인 <style>/style= 은 차단된다.
# 따라서 CSS 는 같은 출처의 /style.css 라우트로 내려보낸다. (JS 는 여전히 0줄)
STYLE = """
:root{
  --void:#06030f;
  --card:#150f38;
  --panel:#1c1550;          /* 메모 본문 배경. .ghost 글자색과 반드시 동일 */
  --ink:#f5efff;
  --muted:#a99ae8;
  --p1:#ff2d95;             /* 핫핑크   */
  --p2:#00e5ff;             /* 시안     */
  --p3:#ffd93d;             /* 옐로     */
  --p4:#9d4edd;             /* 퍼플     */
  --p5:#39ff88;             /* 네온그린 */
}

*{box-sizing:border-box}
html,body{margin:0;padding:0}

body{
  min-height:100vh;
  background:var(--void);
  color:var(--ink);
  font-family:"Trebuchet MS","Segoe UI",Pretendard,"맑은 고딕","Malgun Gothic",sans-serif;
  overflow-x:hidden;
  padding:0 16px 64px;
}

/* ---------- 배경 레이어 ---------- */
.bg-aurora{
  position:fixed; inset:-30%; z-index:-3; pointer-events:none;
  background:
    radial-gradient(38% 38% at 22% 28%, rgba(255,45,149,.85), transparent 70%),
    radial-gradient(34% 34% at 78% 22%, rgba(0,229,255,.75), transparent 70%),
    radial-gradient(40% 40% at 30% 80%, rgba(157,78,221,.85), transparent 70%),
    radial-gradient(30% 30% at 82% 74%, rgba(57,255,136,.55), transparent 70%),
    radial-gradient(28% 28% at 52% 50%, rgba(255,217,61,.55), transparent 70%);
  filter:blur(70px) saturate(160%);
  animation:swirl 22s linear infinite;
}
.bg-grid{
  position:fixed; inset:0; z-index:-2; pointer-events:none; opacity:.22;
  background-image:
    linear-gradient(rgba(0,229,255,.45) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,45,149,.45) 1px, transparent 1px);
  background-size:46px 46px;
  animation:gridrun 4s linear infinite;
}
.bg-scan{
  position:fixed; inset:0; z-index:-1; pointer-events:none; opacity:.16;
  background:repeating-linear-gradient(180deg, rgba(255,255,255,.28) 0 1px, transparent 1px 4px);
  animation:scan 7s linear infinite;
}

/* ---------- 반짝이 ---------- */
.sparkles span{
  position:fixed; z-index:-1; pointer-events:none;
  width:7px; height:7px; border-radius:50%;
  background:#fff; box-shadow:0 0 12px 3px rgba(255,255,255,.9);
  animation:twinkle 2.6s ease-in-out infinite;
}
.sparkles span:nth-child(1){left:6%;  top:12%; animation-delay:0s;    background:var(--p2)}
.sparkles span:nth-child(2){left:18%; top:72%; animation-delay:.35s;  background:var(--p1)}
.sparkles span:nth-child(3){left:31%; top:26%; animation-delay:.7s;   background:var(--p3)}
.sparkles span:nth-child(4){left:44%; top:88%; animation-delay:1.05s; background:var(--p5)}
.sparkles span:nth-child(5){left:57%; top:16%; animation-delay:1.4s;  background:var(--p4)}
.sparkles span:nth-child(6){left:69%; top:64%; animation-delay:1.75s; background:var(--p2)}
.sparkles span:nth-child(7){left:81%; top:34%; animation-delay:2.1s;  background:var(--p1)}
.sparkles span:nth-child(8){left:93%; top:78%; animation-delay:2.45s; background:var(--p3)}
.sparkles span:nth-child(9){left:11%; top:44%; animation-delay:.2s;   background:var(--p5)}
.sparkles span:nth-child(10){left:26%;top:6%;  animation-delay:.9s;   background:var(--p4)}
.sparkles span:nth-child(11){left:63%;top:92%; animation-delay:1.6s;  background:var(--p2)}
.sparkles span:nth-child(12){left:88%;top:8%;  animation-delay:2.3s;  background:var(--p1)}
.sparkles span:nth-child(13){left:49%;top:40%; animation-delay:1.2s;  background:var(--p3)}
.sparkles span:nth-child(14){left:73%;top:52%; animation-delay:.55s;  background:var(--p5)}

/* ---------- 둥둥 떠다니는 이모지 ---------- */
.floaties span{
  position:fixed; z-index:-1; pointer-events:none; user-select:none;
  font-size:clamp(28px,5vw,54px); opacity:.5;
  filter:drop-shadow(0 0 14px rgba(255,255,255,.45));
  animation:float 9s ease-in-out infinite;
}
.floaties span:nth-child(1){left:3%;  top:18%; animation-delay:0s;   animation-duration:8s}
.floaties span:nth-child(2){left:90%; top:14%; animation-delay:.8s;  animation-duration:11s}
.floaties span:nth-child(3){left:7%;  top:62%; animation-delay:1.6s; animation-duration:9.5s}
.floaties span:nth-child(4){left:92%; top:58%; animation-delay:2.4s; animation-duration:12s}
.floaties span:nth-child(5){left:14%; top:88%; animation-delay:3.2s; animation-duration:10s}
.floaties span:nth-child(6){left:84%; top:86%; animation-delay:4s;   animation-duration:8.5s}
.floaties span:nth-child(7){left:47%; top:4%;  animation-delay:1.1s; animation-duration:13s}

/* ---------- 레이아웃 ---------- */
.shell{max-width:660px; margin:0 auto; padding-top:26px}

/* ---------- 헤더 ---------- */
.ticker{
  overflow:hidden; white-space:nowrap; border-radius:999px;
  border:2px solid rgba(0,229,255,.55);
  background:linear-gradient(90deg, rgba(255,45,149,.3), rgba(0,229,255,.3), rgba(157,78,221,.3));
  box-shadow:0 0 26px rgba(0,229,255,.45);
  padding:7px 0; margin-bottom:20px; font-size:13px; letter-spacing:.16em;
}
.ticker-track{display:inline-block; animation:slide 16s linear infinite; padding-left:100%}
.ticker-track b{color:var(--p3); text-shadow:0 0 10px var(--p3)}

.masthead{text-align:center; margin-bottom:22px}
.logo{
  margin:0; font-size:clamp(2.1rem,8.5vw,3.5rem); line-height:1.15;
  letter-spacing:-.02em; font-weight:900;
}
.logo-emoji{
  display:inline-block; margin-right:.2em;
  filter:drop-shadow(0 0 16px var(--p3));
  animation:wobble 1.6s ease-in-out infinite;
}
.logo-text{
  background:linear-gradient(90deg,var(--p1),var(--p3),var(--p5),var(--p2),var(--p4),var(--p1));
  background-size:300% 100%;
  -webkit-background-clip:text; background-clip:text; color:transparent;
  animation:rainbow 4.5s linear infinite;
}
.tagline{
  margin:10px 0 0; font-size:13.5px; color:var(--muted); letter-spacing:.1em;
  animation:blink 2.2s steps(1) infinite;
}

/* ---------- 카드 ---------- */
.card{
  position:relative; z-index:0;
  background:var(--card);
  border-radius:24px;
  padding:26px 24px 30px;
  box-shadow:
    0 0 0 2px rgba(255,255,255,.08),
    0 26px 70px rgba(0,0,0,.6),
    0 0 60px rgba(255,45,149,.28),
    0 0 110px rgba(0,229,255,.18);
  animation:cardin .5s cubic-bezier(.2,1.4,.4,1) both;
}
.card::before{
  content:""; position:absolute; inset:-3px; z-index:-1; border-radius:27px;
  background:conic-gradient(from 0deg,var(--p1),var(--p2),var(--p3),var(--p5),var(--p4),var(--p1));
  filter:blur(9px); opacity:.85;
  animation:spin 5s linear infinite;
}

h2{
  margin:0 0 6px; font-size:1.5rem; letter-spacing:-.01em;
  text-shadow:0 0 18px rgba(0,229,255,.8), 0 0 40px rgba(255,45,149,.5);
}
h3{
  margin:22px 0 10px; font-size:1.08rem; color:var(--p2);
  text-shadow:0 0 14px rgba(0,229,255,.75);
}
p{margin:9px 0; line-height:1.65}
small{color:var(--muted)}
i{color:var(--muted)}

hr{
  border:0; height:3px; margin:20px 0; border-radius:3px;
  background:linear-gradient(90deg,var(--p1),var(--p3),var(--p5),var(--p2),var(--p4));
  background-size:200% 100%;
  animation:rainbow 3s linear infinite;
  box-shadow:0 0 16px rgba(255,45,149,.7);
}

a{color:var(--p2); text-decoration:none; font-weight:700}
a:hover{color:var(--p3); text-shadow:0 0 14px var(--p3)}

/* ---------- 플래시 메시지 ---------- */
.flash{
  margin:0 0 18px; padding:12px 16px; border-radius:14px;
  border:2px solid var(--p3);
  background:linear-gradient(90deg, rgba(255,217,61,.2), rgba(255,45,149,.2));
  box-shadow:0 0 28px rgba(255,217,61,.5);
  font-weight:700;
  animation:shake .5s ease-in-out 2, glowpulse 1.6s ease-in-out infinite;
}
.flash b{display:block; padding:2px 0}

/* ---------- 버튼 ---------- */
button{
  position:relative; overflow:hidden; cursor:pointer;
  font:inherit; font-weight:800; font-size:14.5px;
  color:#0b0620; padding:11px 20px; margin:4px 4px 4px 0;
  border:0; border-radius:999px;
  background:linear-gradient(120deg,var(--p2),var(--p5),var(--p3),var(--p1));
  background-size:280% 100%;
  box-shadow:0 8px 24px rgba(0,229,255,.4), 0 0 0 2px rgba(255,255,255,.18) inset;
  transition:transform .15s ease, box-shadow .2s ease, filter .2s ease;
  animation:rainbow 5s linear infinite;
}
button:hover{
  transform:translateY(-3px) scale(1.05) rotate(-1deg);
  box-shadow:0 14px 34px rgba(255,45,149,.55), 0 0 26px rgba(255,217,61,.7);
  filter:saturate(150%);
}
button:active{transform:translateY(0) scale(.97)}
button::after{
  content:""; position:absolute; top:0; left:-60%; width:40%; height:100%;
  background:linear-gradient(100deg, transparent, rgba(255,255,255,.75), transparent);
  animation:shine 2.6s linear infinite;
}
form{margin:0}
a > button{margin-left:0}

/* ---------- 폼 ---------- */
.form-grid{border-collapse:separate; border-spacing:0 12px; width:100%}
.form-grid td{padding:0 6px; vertical-align:middle}
.form-grid td.label{
  width:34%; text-align:right; color:var(--p2); font-weight:800; font-size:14px;
  text-shadow:0 0 12px rgba(0,229,255,.6);
}
input[type=text],input[type=password],textarea{
  width:100%; max-width:100%; font:inherit; font-size:15px;
  color:var(--ink); background:var(--panel);
  border:2px solid rgba(157,78,221,.65); border-radius:12px;
  padding:11px 13px; outline:none;
  transition:border-color .2s, box-shadow .2s, transform .2s;
}
textarea{min-height:190px; resize:vertical; line-height:1.6}
input:focus,textarea:focus{
  border-color:var(--p1);
  box-shadow:0 0 0 4px rgba(255,45,149,.25), 0 0 26px rgba(255,45,149,.6);
  transform:scale(1.015);
}
input::placeholder{color:rgba(169,154,232,.6)}

/* ---------- 표 ---------- */
.grid{width:100%; border-collapse:separate; border-spacing:0 8px; font-size:14px}
.grid th{
  padding:11px 10px; text-align:left; font-size:12px; letter-spacing:.12em;
  color:#0b0620; background:linear-gradient(90deg,var(--p2),var(--p5),var(--p3));
  background-size:220% 100%; animation:rainbow 6s linear infinite;
}
.grid th:first-child{border-radius:12px 0 0 12px}
.grid th:last-child{border-radius:0 12px 12px 0}
.grid td{
  padding:12px 10px; background:var(--panel);
  border-top:1px solid rgba(255,255,255,.07);
  border-bottom:1px solid rgba(0,0,0,.35);
}
.grid td:first-child{border-radius:12px 0 0 12px; border-left:3px solid var(--p1)}
.grid td:last-child{border-radius:0 12px 12px 0; border-right:3px solid var(--p2)}
.grid tbody tr{transition:transform .18s ease, filter .18s ease}
/* hover 시 배경/글자에 동일한 필터만 적용 -> 숨김 메모(.ghost) 대비는 그대로 유지 */
.grid tbody tr:hover{transform:translateX(5px); filter:brightness(1.25) saturate(130%)}
.grid .c{text-align:center}

/* ---------- 메모 본문 ---------- */
.memo-body{
  margin:0; padding:18px; border-radius:16px;
  background:var(--panel); border:2px dashed rgba(0,229,255,.45);
  box-shadow:inset 0 0 30px rgba(0,0,0,.45);
  font-family:"Cascadia Mono",Consolas,"D2Coding",monospace;
  font-size:15px; line-height:1.7; white-space:pre-wrap; word-break:break-word;
}
/* 배경색과 완전히 동일한 글자색(드래그/소스보기 시에만 보임) */
.ghost{color:var(--panel)}

.count{
  display:inline-block; padding:5px 14px; border-radius:999px;
  background:rgba(157,78,221,.28); border:1px solid rgba(157,78,221,.7);
  color:var(--p3); font-weight:800; font-size:12.5px;
}
.empty{
  padding:26px; border-radius:16px; text-align:center;
  border:2px dashed rgba(255,45,149,.45); background:rgba(255,45,149,.08);
}
.row{display:flex; flex-wrap:wrap; gap:8px; align-items:center}
.footnote{
  margin-top:22px; text-align:center; font-size:12px; color:var(--muted);
  letter-spacing:.14em;
}
.footnote span{
  display:inline-block; animation:wobble 2.4s ease-in-out infinite;
}

/* ---------- 키프레임 ---------- */
@keyframes swirl{
  0%{transform:rotate(0deg) scale(1)}
  50%{transform:rotate(180deg) scale(1.18)}
  100%{transform:rotate(360deg) scale(1)}
}
@keyframes gridrun{to{background-position:46px 46px, 46px 46px}}
@keyframes scan{to{background-position:0 400px}}
@keyframes twinkle{
  0%,100%{opacity:0; transform:scale(.3)}
  50%{opacity:1; transform:scale(1.5)}
}
@keyframes float{
  0%,100%{transform:translateY(0) rotate(-12deg)}
  50%{transform:translateY(-38px) rotate(14deg)}
}
@keyframes rainbow{to{background-position:300% 50%}}
@keyframes wobble{
  0%,100%{transform:rotate(-14deg) scale(1)}
  50%{transform:rotate(14deg) scale(1.15)}
}
@keyframes blink{50%{opacity:.35}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes slide{to{transform:translateX(-100%)}}
@keyframes shine{0%{left:-60%}60%,100%{left:130%}}
@keyframes shake{
  0%,100%{transform:translateX(0)}
  25%{transform:translateX(-7px) rotate(-1deg)}
  75%{transform:translateX(7px) rotate(1deg)}
}
@keyframes glowpulse{
  0%,100%{box-shadow:0 0 22px rgba(255,217,61,.4)}
  50%{box-shadow:0 0 42px rgba(255,45,149,.75)}
}
@keyframes cardin{
  from{opacity:0; transform:translateY(26px) scale(.94) rotate(-1.5deg)}
  to{opacity:1; transform:none}
}

@media (max-width:480px){
  .card{padding:20px 16px 24px}
  .form-grid td.label{width:auto; text-align:left; display:block; padding-bottom:4px}
  .form-grid td{display:block; padding:0}
  .form-grid{border-spacing:0}
  .form-grid tr{display:block; margin-bottom:12px}
}

@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation:none !important; transition:none !important}
}
"""

# ---------------------------------------------------------------------------
# HTML 템플릿
# ---------------------------------------------------------------------------
BASE = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모 서비스</title>
  <link rel="stylesheet" href="{{ url_for('stylesheet') }}">
</head>
<body>
  <div class="bg-aurora"></div>
  <div class="bg-grid"></div>
  <div class="bg-scan"></div>
  <div class="sparkles">
    <span></span><span></span><span></span><span></span><span></span>
    <span></span><span></span><span></span><span></span><span></span>
    <span></span><span></span><span></span><span></span>
  </div>
  <div class="floaties">
    <span>&#128221;</span><span>&#10024;</span><span>&#128190;</span>
    <span>&#128640;</span><span>&#127752;</span><span>&#9889;</span>
    <span>&#128142;</span>
  </div>

  <div class="shell">
    <div class="ticker">
      <div class="ticker-track">
        &#10024; MEMO SERVICE &#10024; <b>SUPER MEGA ULTRA</b> &#10024; 적어라 &#10024;
        기억하지 마라 &#10024; <b>2026</b> &#10024; MEMO SERVICE &#10024;
        <b>SUPER MEGA ULTRA</b> &#10024; 적어라 &#10024; 기억하지 마라 &#10024;
      </div>
    </div>

    <header class="masthead">
      <h1 class="logo"><span class="logo-emoji">&#128221;</span><span class="logo-text">메모 서비스</span></h1>
      <p class="tagline">&#9889; 세상에서 제일 화려한 메모장 &#9889;</p>
    </header>

    <main class="card">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class="flash">
            {% for m in messages %}
              <b>&#9888; {{ m }}</b>
            {% endfor %}
          </div>
        {% endif %}
      {% endwith %}
      {{ body | safe }}
    </main>

    <p class="footnote">
      <span>&#127752;</span> MEMO &#183; SERVICE &#183; {{ title }} <span>&#127752;</span>
    </p>
  </div>
</body>
</html>
"""

HOME = """
<h2>{{ user['username'] }}님, 환영합니다! &#128075;</h2>
<p>로그인이 유지되고 있습니다. &#128293;</p>
<p><small>&#128197; 가입일: {{ user['created_at'] }}</small></p>
<hr>
<h3>&#128203; 내 메모</h3>
<p>
  <a href="{{ url_for('memo_new') }}">
    <button type="button">&#10133; 새 메모 작성</button>
  </a>
</p>
{% if memos %}
  <table class="grid">
    <thead>
      <tr><th class="c">번호</th><th>내용</th><th>작성일</th><th class="c">보기</th></tr>
    </thead>
    <tbody>
    {% for m in memos %}
      <tr>
        <td class="c">{{ m['id'] }}</td>
        {# 관리자(=flag 보유자)의 메모는 배경과 같은 색으로 표시해 눈에 잘 안 띄게 함.
           일반 사용자 메모는 정상 표시. (드래그/소스보기 시엔 보임 - 눈속임용) #}
        <td>{% if user['is_admin'] %}<span class="ghost">{{ m['content'] | truncate(40, True) }}</span>{% else %}{{ m['content'] | truncate(40, True) }}{% endif %}</td>
        <td><small>{{ m['created_at'] }}</small></td>
        <td class="c"><a href="{{ url_for('memo_detail', memo_id=m['id']) }}">보기 &#8594;</a></td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
{% else %}
  <p class="empty"><i>&#128172; 아직 작성한 메모가 없습니다.</i></p>
{% endif %}
<hr>
<div class="row">
  {% if user['is_admin'] %}
    <a href="{{ url_for('admin') }}">
      <button type="button">&#128273; 관리자 페이지</button>
    </a>
  {% endif %}
  <form method="post" action="{{ url_for('logout') }}">
    <button type="submit">&#128682; 로그아웃</button>
  </form>
</div>
"""

ADMIN = """
<h2>&#128273; 관리자 페이지</h2>
<p>전체 회원 목록입니다. <small>(관리자만 접근 가능)</small></p>
<hr>
<table class="grid">
  <thead>
    <tr><th class="c">ID</th><th>아이디</th><th class="c">관리자</th><th>가입일</th></tr>
  </thead>
  <tbody>
  {% for u in users %}
    <tr>
      <td class="c">{{ u['id'] }}</td>
      <td>{{ u['username'] }}</td>
      <td class="c">{{ '&#9989;' | safe if u['is_admin'] else '-' }}</td>
      <td><small>{{ u['created_at'] }}</small></td>
    </tr>
  {% endfor %}
  </tbody>
</table>
<p><span class="count">&#128101; 총 {{ users | length }}명</span></p>
<hr>
<p><a href="{{ url_for('home') }}">&#8592; 홈으로</a></p>
"""

# 새 메모 작성 / 수정 공용 폼
MEMO_FORM = """
<h2>{{ '&#9999; 메모 수정' | safe if memo else '&#10133; 새 메모 작성' | safe }}</h2>
<p><small>&#10024; 떠오르는 대로 마구 적어보세요</small></p>
<hr>
<form method="post" action="{{ action }}">
  <p>
    <textarea name="content" rows="8" required autofocus placeholder="여기에 입력...">{{ memo['content'] if memo else '' }}</textarea>
  </p>
  <div class="row">
    <button type="submit">&#128190; 저장</button>
    <a href="{{ url_for('home') }}"><button type="button">&#10060; 취소</button></a>
  </div>
</form>
"""

# 메모 상세 조회
MEMO_DETAIL = """
<h2>&#128203; 메모 상세</h2>
<p><small>&#35; {{ memo['id'] }} &#183; &#128197; {{ memo['created_at'] }}</small></p>
<hr>
<pre class="memo-body">{% if user['is_admin'] %}<span class="ghost">{{ memo['content'] }}</span>{% else %}{{ memo['content'] }}{% endif %}</pre>
<hr>
<div class="row">
  <a href="{{ url_for('memo_edit', memo_id=memo['id']) }}">
    <button type="button">&#9999; 수정</button>
  </a>
  <form method="post" action="{{ url_for('memo_delete', memo_id=memo['id']) }}">
    <button type="submit">&#128465; 삭제</button>
  </form>
</div>
<hr>
<p><a href="{{ url_for('home') }}">&#8592; 목록으로</a></p>
"""

LOGIN = """
<h2>&#128273; 로그인</h2>
<p><small>&#10024; 돌아오신 걸 환영합니다</small></p>
<hr>
<form method="post" action="{{ url_for('login') }}">
  <table class="form-grid">
    <tr>
      <td class="label"><label for="username">아이디</label></td>
      <td><input type="text" id="username" name="username" required autofocus></td>
    </tr>
    <tr>
      <td class="label"><label for="password">비밀번호</label></td>
      <td><input type="password" id="password" name="password" required></td>
    </tr>
    <tr>
      <td class="label"></td>
      <td><button type="submit">&#128273; 로그인</button></td>
    </tr>
  </table>
</form>
<hr>
<p>계정이 없으신가요? <a href="{{ url_for('register') }}">회원가입 &#8594;</a></p>
"""

REGISTER = """
<h2>&#9989; 회원가입</h2>
<p><small>&#127881; 30초면 충분합니다</small></p>
<hr>
<form method="post" action="{{ url_for('register') }}">
  <table class="form-grid">
    <tr>
      <td class="label"><label for="username">아이디</label></td>
      <td><input type="text" id="username" name="username" required autofocus></td>
    </tr>
    <tr>
      <td class="label"><label for="password">비밀번호</label></td>
      <td><input type="password" id="password" name="password" required></td>
    </tr>
    <tr>
      <td class="label"><label for="password2">비밀번호 확인</label></td>
      <td><input type="password" id="password2" name="password2" required></td>
    </tr>
    <tr>
      <td class="label"></td>
      <td><button type="submit">&#9989; 가입하기</button></td>
    </tr>
  </table>
</form>
<hr>
<p>이미 계정이 있으신가요? <a href="{{ url_for('login') }}">로그인 &#8594;</a></p>
"""


def page(title, body_template, **context):
    """공통 레이아웃(BASE) 안에 개별 페이지 본문을 렌더링한다."""
    body = render_template_string(body_template, **context)
    return render_template_string(BASE, title=title, body=body)


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route("/style.css")
def stylesheet():
    """[보안] CSP(default-src 'self') 하에서 인라인 스타일은 차단되므로
    스타일시트를 같은 출처의 정적 응답으로 내려준다."""
    resp = app.response_class(STYLE, mimetype="text/css")
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


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


# ---------------------------------------------------------------------------
# Notes API (/api/*)
# ---------------------------------------------------------------------------
# 모든 응답(에러 포함)은 JSON. 세션은 기존 웹 로그인과 동일한 쿠키/지문 방식을
# 그대로 재사용한다(current_user()). 웹 라우트 동작에는 영향을 주지 않는다.
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """[API] /api/* 경로의 에러는 HTML 대신 JSON 으로 응답한다."""
    if request.path.startswith("/api/"):
        return jsonify({"error": e.description}), e.code
    return e  # 웹 페이지는 기존 동작(HTML) 유지


def api_error(status, message):
    return jsonify({"error": message}), status


def note_json(row):
    """note 객체 직렬화. id 는 정수, 나머지는 문자열."""
    return {
        "id": int(row["id"]),
        "title": row["title"],
        "body": row["body"] if row["body"] is not None else "",
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


@app.route("/api/notes", methods=["GET"])
def api_notes_list():
    user = current_user()
    if user is None:
        return api_error(401, "authentication required")
    rows = get_db().execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC", (user["id"],)
    ).fetchall()
    return jsonify({"notes": [note_json(r) for r in rows]}), 200


@app.route("/api/notes", methods=["POST"])
def api_notes_create():
    user = current_user()
    if user is None:
        return api_error(401, "authentication required")

    # force=True: Content-Type 헤더가 없거나 틀려도 본문이 JSON 이면 받아준다.
    # (curl -d '{...}' 처럼 헤더를 생략한 호출도 통과시키기 위함)
    data = request.get_json(silent=True, force=True)
    if not isinstance(data, dict):
        return api_error(400, "JSON object body required")

    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        return api_error(400, "title is required")

    body = data.get("body", "")
    if body is None:
        body = ""
    if not isinstance(body, str):
        return api_error(400, "body must be a string")

    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (user["id"], title.strip(), body),
    )
    db.commit()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(note_json(row)), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
def api_notes_detail(note_id):
    user = current_user()
    if user is None:
        return api_error(401, "authentication required")
    row = get_db().execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    # [보안] 소유권 격리: 남의 노트도 404 로 처리해 존재 여부 자체를 숨긴다.
    if row is None or row["user_id"] != user["id"]:
        return api_error(404, "note not found")
    return jsonify(note_json(row)), 200


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
