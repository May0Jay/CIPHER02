"""Myphema backend: auth (signup/signin + email OTP), sessions, dashboard API."""
import os, re, time, uuid, hmac, hashlib, secrets, sqlite3, smtplib, random
from email.message import EmailMessage
from functools import wraps
import jwt
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "myphema.db"))
DEV_MODE = os.environ.get("DEV_MODE", "0") == "1"
ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
SECRET = os.environ.get("JWT_SECRET")
if not SECRET:  # zero-config: create once, reuse on restart
    _p = os.path.join(HERE, ".secret")
    if os.path.exists(_p): SECRET = open(_p).read().strip()
    else:
        SECRET = secrets.token_hex(32)
        open(_p, "w").write(SECRET)
    print("[info] JWT_SECRET not set - using the key stored in backend/.secret")
OTP_TTL, OTP_MAX_TRIES, RESEND_GAP = 600, 5, 30
SESSION_TTL, RESET_TTL = 8 * 3600, 900
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
DUMMY_HASH = generate_password_hash("dummy-password")

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
        pw_hash TEXT, verified INTEGER DEFAULT 0, created_at INTEGER);
    CREATE TABLE IF NOT EXISTS otps(email TEXT, purpose TEXT, code_hash TEXT, expires INTEGER,
        tries INTEGER DEFAULT 0, sent_at INTEGER, PRIMARY KEY(email, purpose));
    CREATE TABLE IF NOT EXISTS revoked(jti TEXT PRIMARY KEY, exp INTEGER);
    CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, title TEXT, employee TEXT, dept TEXT,
        score INTEGER, status TEXT, detected_at INTEGER, source TEXT, host TEXT, dest TEXT,
        size TEXT, files INTEGER);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER, user_id INTEGER, action TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS employees(name TEXT PRIMARY KEY, dept TEXT, role TEXT, risk INTEGER, gb REAL, status TEXT);
    CREATE TABLE IF NOT EXISTS endpoints(host TEXT PRIMARY KEY, usr TEXT, dept TEXT, os TEXT, osv TEXT, ip TEXT, agent TEXT,
        status TEXT, last_seen INTEGER, risk INTEGER, out_gb REAL, usb INTEGER, usb_blocked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, ts INTEGER, actor TEXT, cat TEXT, text TEXT, ref TEXT);
    """)
    if not c.execute("SELECT 1 FROM incidents").fetchone():
        now = int(time.time()); h = 3600
        c.executemany("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", [
            ("INC-2041", "Bulk upload to personal cloud", "R. Verma", "Finance", 87, "open", now-120, "Finance share", "WS-0412", "Personal Drive", "1.8 GB", 312),
            ("INC-2040", "USB copy of source code", "A. Khan", "Engineering", 64, "open", now-3*h, "Repo checkout", "WS-0233", "USB drive", "640 MB", 88),
            ("INC-2039", "Large email attachments", "P. Iyer", "Sales", 52, "open", now-26*h, "CRM export", "WS-0107", "External email", "210 MB", 14),
            ("INC-2038", "Off-hours database export", "S. Rao", "Support", 31, "resolved", now-3*86400, "Support DB", "WS-0319", "Local disk", "90 MB", 3),
            ("INC-2037", "Mass download from HR portal", "M. Nair", "HR", 71, "open", now-5*h, "HR portal", "WS-0150", "Local disk", "1.1 GB", 540),
            ("INC-2036", "Credentials sent to personal email", "D. Sethi", "IT", 92, "blocked", now-2*86400, "Password vault", "WS-0021", "Personal email", "4 MB", 6),
            ("INC-2035", "Large print job", "K. Das", "Legal", 28, "false_positive", now-4*86400, "Contracts share", "WS-0388", "Network printer", "48 MB", 120),
            ("INC-2034", "Source repo cloned to external host", "V. Menon", "Engineering", 58, "investigating", now-6*h, "Git server", "WS-0275", "External server", "2.4 GB", 1900)])
    t0 = int(time.time())
    if not c.execute("SELECT 1 FROM employees").fetchone():
        c.executemany("INSERT INTO employees VALUES(?,?,?,?,?,?)", [
            ("D. Sethi","IT","Systems Administrator",92,.4,"watchlist"),("R. Verma","Finance","Senior Accountant",87,14.2,"watchlist"),
            ("M. Nair","HR","HR Manager",71,6.8,"active"),("A. Khan","Engineering","Backend Engineer",64,9.1,"active"),
            ("V. Menon","Engineering","DevOps Engineer",58,22.5,"active"),("P. Iyer","Sales","Account Executive",52,3.3,"active"),
            ("S. Rao","Support","Support Lead",31,1.2,"active"),("K. Das","Legal","Legal Counsel",28,2,"active"),
            ("P. Kapoor","Support","Support Agent",22,.8,"active"),("T. Joshi","Sales","Sales Associate",18,1.1,"active"),
            ("N. Gupta","Finance","Financial Analyst",12,.9,"active"),("L. Sharma","HR","Recruiter",9,.5,"suspended")])
        c.executemany("INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)", [(h,u,d,o,ov,ip,ag,st,t0-m*60,rk,out,usb) for h,u,d,o,ov,ip,ag,st,m,rk,out,usb in [
            ("WS-0412","R. Verma","Finance","Windows","Windows 11","10.0.4.112","5.2.1","online",0,87,1.9,0),("WS-0021","D. Sethi","IT","Windows","Windows 11","10.0.1.21","5.2.1","isolated",2,92,.1,0),
            ("WS-0150","M. Nair","HR","Windows","Windows 11","10.0.5.50","5.2.1","online",1,71,1.2,0),("WS-0233","A. Khan","Engineering","Linux","Ubuntu 22.04","10.0.7.33","5.2.1","online",0,64,.7,1),
            ("WS-0275","V. Menon","Engineering","Linux","Ubuntu 22.04","10.0.7.75","5.2.0","online",3,58,2.5,0),("WS-0107","P. Iyer","Sales","macOS","macOS 14","10.0.2.17","5.1.4","online",4,52,.3,0),
            ("SRV-DB01","Database server","IT","Linux","Debian 12","10.0.9.10","5.2.1","online",0,44,6.4,0),("SRV-FS02","File server","IT","Windows","Windows Server 2022","10.0.9.20","5.2.1","online",0,36,3.1,0),
            ("WS-0319","S. Rao","Support","Windows","Windows 10","10.0.3.19","5.1.4","offline",4320,31,0,0),("WS-0388","K. Das","Legal","macOS","macOS 14","10.0.6.88","5.2.1","online",2,28,.2,0),
            ("WS-0090","P. Kapoor","Support","Windows","Windows 11","10.0.3.90","5.2.1","online",1,22,.4,0),("WS-0144","T. Joshi","Sales","macOS","macOS 13","10.0.2.44","5.0.9","offline",130,18,0,0),
            ("WS-0301","N. Gupta","Finance","Windows","Windows 11","10.0.4.30","5.2.1","online",0,12,.3,0),("WS-0066","L. Sharma","HR","Windows","Windows 10","10.0.5.66","5.1.4","offline",10080,9,0,0)]])
        c.executemany("INSERT INTO history(ts,actor,cat,text,ref) VALUES(?,?,?,?,?)", [(t0-m*60,b,ct,tx,rf) for m,b,ct,tx,rf in [
            (2,"System","alert","Alert raised: Bulk upload to personal cloud","INC-2041"),(180,"System","alert","Alert raised: USB copy of source code","INC-2040"),
            (180,"System","endpoint","USB device connected (Kingston 64 GB)","WS-0233"),(300,"System","alert","Alert raised: Mass download from HR portal","INC-2037"),
            (360,"System","alert","Alert raised: Source repo cloned externally","INC-2034"),(130,"System","endpoint","Device went offline","WS-0144"),
            (1560,"System","alert","Alert raised: Large email attachments","INC-2039"),(2880,"System","alert","Alert raised: Credentials sent to personal email","INC-2036"),
            (2880,"Security team","alert","Transfer blocked","INC-2036"),(2880,"Security team","endpoint","Device isolated","WS-0021"),
            (4000,"Security team","employee","Added to watchlist","D. Sethi"),(4320,"Security team","alert","Incident resolved","INC-2038"),
            (4320,"System","endpoint","Device went offline","WS-0319"),(5760,"Security team","alert","Marked as false positive","INC-2035"),
            (10080,"Security team","employee","Access suspended (on leave)","L. Sharma")]])
    c.commit(); c.close()

def hlog(cat, text, ref, actor=None):
    if actor is None: actor = g.user["name"] if "user" in g else "System"
    db().execute("INSERT INTO history(ts,actor,cat,text,ref) VALUES(?,?,?,?,?)", (int(time.time()), actor, cat, text, ref))
    db().commit()

def audit(action, detail="", uid=None):
    db().execute("INSERT INTO audit(ts,user_id,action,detail) VALUES(?,?,?,?)", (int(time.time()), uid, action, detail))
    db().commit()

# ---------- helpers ----------
def err(msg, code=400, **extra):
    return jsonify(error=msg, **extra), code

_hits = {}
def limited(key, limit=15, window=60):
    now = time.time()
    q = [t for t in _hits.get(key, []) if now - t < window]
    q.append(now); _hits[key] = q
    return len(q) > limit

def rate_limit(f):
    @wraps(f)
    def w(*a, **k):
        if limited(f"{request.remote_addr}:{request.endpoint}"):
            return err("Too many requests. Please slow down.", 429)
        return f(*a, **k)
    return w

def body():
    return request.get_json(silent=True) or {}

def norm_email(v):
    return (v or "").strip().lower()

def pw_problem(p):
    if len(p or "") < 8: return "Password must be at least 8 characters"
    if sum([bool(re.search(r"[a-z]", p) and re.search(r"[A-Z]", p)), bool(re.search(r"\d", p)), bool(re.search(r"[^A-Za-z0-9]", p))]) < 2:
        return "Add upper & lower case letters, a number or a symbol"
    return None

def send_mail(to, subject, text):
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"\n[email -> {to}] {subject}\n{text}\n"); return
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = os.environ.get("SMTP_FROM", "Myphema <no-reply@localhost>"), to, subject
    m.set_content(text)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"): s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
        s.send_message(m)

def hash_code(email, purpose, code):
    return hmac.new(SECRET.encode(), f"{email}|{purpose}|{code}".encode(), hashlib.sha256).hexdigest()

def issue_otp(email, purpose):
    """Create + email a 6-digit code. Returns (ok, retry_after, code)."""
    row = db().execute("SELECT sent_at FROM otps WHERE email=? AND purpose=?", (email, purpose)).fetchone()
    now = int(time.time())
    if row and now - row["sent_at"] < RESEND_GAP:
        return False, RESEND_GAP - (now - row["sent_at"]), None
    code = f"{secrets.randbelow(10**6):06d}"
    db().execute("REPLACE INTO otps VALUES(?,?,?,?,0,?)", (email, purpose, hash_code(email, purpose, code), now + OTP_TTL, now))
    db().commit()
    send_mail(email, "Your Myphema verification code",
              f"Your Myphema code is {code}. It expires in {OTP_TTL // 60} minutes.\nIf you didn't request this, ignore this email.")
    return True, 0, code

def otp_response(purpose, code, **extra):
    r = dict(otpRequired=True, purpose=purpose, expiresIn=OTP_TTL, resendIn=RESEND_GAP, **extra)
    if DEV_MODE and code: r["devCode"] = code
    return jsonify(r)

def make_token(uid, typ="access", ttl=SESSION_TTL):
    now = int(time.time())
    return jwt.encode({"sub": str(uid), "jti": uuid.uuid4().hex, "typ": typ, "iat": now, "exp": now + ttl}, SECRET, algorithm="HS256")

def decode(token, typ):
    p = jwt.decode(token, SECRET, algorithms=["HS256"])
    if p.get("typ") != typ: raise jwt.InvalidTokenError("wrong type")
    if db().execute("SELECT 1 FROM revoked WHERE jti=?", (p["jti"],)).fetchone(): raise jwt.InvalidTokenError("revoked")
    return p

def auth_required(f):
    @wraps(f)
    def w(*a, **k):
        h = request.headers.get("Authorization", "")
        try:
            p = decode(h[7:], "access") if h.startswith("Bearer ") else None
            if not p: raise jwt.InvalidTokenError()
        except jwt.PyJWTError:
            return err("Not signed in or session expired", 401)
        u = db().execute("SELECT * FROM users WHERE id=?", (p["sub"],)).fetchone()
        if not u: return err("Account not found", 401)
        g.user, g.claims = u, p
        return f(*a, **k)
    return w

def public_user(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"]}

# ---------- CORS / headers ----------
@app.before_request
def preflight():
    if request.method == "OPTIONS": return "", 204

@app.after_request
def headers(r):
    r.headers["Access-Control-Allow-Origin"] = ORIGIN
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Cache-Control"] = "no-store" if request.path.startswith("/api") else r.headers.get("Cache-Control", "")
    return r

# ---------- auth routes ----------
@app.post("/api/auth/signup")
@rate_limit
def signup():
    d = body(); name, email = (d.get("name") or "").strip(), norm_email(d.get("email"))
    pw, cp = d.get("password") or "", d.get("confirmPassword") or ""
    if len(name) < 2: return err("Enter your full name")
    if not EMAIL_RE.match(email): return err("Enter a valid email")
    if (p := pw_problem(pw)): return err(p)
    if pw != cp: return err("Passwords do not match")
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u and u["verified"]: return err("An account with this email already exists", 409)
    h = generate_password_hash(pw)
    if u: db().execute("UPDATE users SET name=?, pw_hash=? WHERE id=?", (name, h, u["id"]))
    else: db().execute("INSERT INTO users(name,email,pw_hash,created_at) VALUES(?,?,?,?)", (name, email, h, int(time.time())))
    db().commit()
    ok, wait, code = issue_otp(email, "signup")
    if not ok: return err(f"Please wait {wait}s before requesting another code", 429, retryAfter=wait)
    return otp_response("signup", code, email=email), 201

@app.post("/api/auth/signin")
@rate_limit
def signin():
    d = body(); email, pw = norm_email(d.get("email")), d.get("password") or ""
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    ok = check_password_hash(u["pw_hash"] if u else DUMMY_HASH, pw)
    if not (u and ok):
        audit("signin_failed", email)
        return err("Invalid email or password", 401)
    purpose = "signin" if u["verified"] else "signup"
    sent, wait, code = issue_otp(email, purpose)
    if not sent: return err(f"Please wait {wait}s before requesting another code", 429, retryAfter=wait)
    return otp_response(purpose, code, email=email)

@app.post("/api/auth/resend-otp")
@rate_limit
def resend():
    d = body(); email, purpose = norm_email(d.get("email")), d.get("purpose")
    if purpose not in ("signup", "signin", "reset"): return err("Invalid purpose")
    pending = db().execute("SELECT 1 FROM otps WHERE email=? AND purpose=?", (email, purpose)).fetchone()
    if not pending: return err("No verification in progress. Please start again.", 404)
    ok, wait, code = issue_otp(email, purpose)
    if not ok: return err(f"Please wait {wait}s before requesting another code", 429, retryAfter=wait)
    return otp_response(purpose, code, email=email)

@app.post("/api/auth/verify-otp")
@rate_limit
def verify():
    d = body(); email, purpose, code = norm_email(d.get("email")), d.get("purpose"), str(d.get("code") or "")
    if purpose not in ("signup", "signin", "reset") or not re.fullmatch(r"\d{6}", code):
        return err("Enter the 6-digit code")
    row = db().execute("SELECT * FROM otps WHERE email=? AND purpose=?", (email, purpose)).fetchone()
    if not row: return err("Code expired or not requested. Request a new one.", 400)
    if row["expires"] < time.time() or row["tries"] >= OTP_MAX_TRIES:
        db().execute("DELETE FROM otps WHERE email=? AND purpose=?", (email, purpose)); db().commit()
        return err("Code expired or too many attempts. Request a new one.", 400)
    if not hmac.compare_digest(row["code_hash"], hash_code(email, purpose, code)):
        db().execute("UPDATE otps SET tries=tries+1 WHERE email=? AND purpose=?", (email, purpose)); db().commit()
        return err("Incorrect code. Please try again.", 400, attemptsLeft=OTP_MAX_TRIES - row["tries"] - 1)
    db().execute("DELETE FROM otps WHERE email=? AND purpose=?", (email, purpose))
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u: return err("Account not found", 404)
    if purpose == "reset":
        db().commit()
        return jsonify(resetToken=make_token(u["id"], "reset", RESET_TTL))
    if purpose == "signup": db().execute("UPDATE users SET verified=1 WHERE id=?", (u["id"],))
    db().commit()
    audit("signin" if purpose == "signin" else "signup", email, u["id"])
    return jsonify(token=make_token(u["id"]), user=public_user(u), expiresIn=SESSION_TTL)

@app.post("/api/auth/forgot-password")
@rate_limit
def forgot():
    email = norm_email(body().get("email"))
    if not EMAIL_RE.match(email): return err("Enter a valid email")
    u = db().execute("SELECT 1 FROM users WHERE email=? AND verified=1", (email,)).fetchone()
    code = None
    if u:
        ok, wait, code = issue_otp(email, "reset")
        if not ok: return err(f"Please wait {wait}s before requesting another code", 429, retryAfter=wait)
    else:  # same response either way: don't reveal which emails exist
        db().execute("REPLACE INTO otps VALUES(?,?,?,?,0,?)", (email, "reset", "x", int(time.time()) + OTP_TTL, int(time.time()))); db().commit()
    return otp_response("reset", code, email=email)

@app.post("/api/auth/reset-password")
@rate_limit
def reset():
    d = body()
    try: p = decode(d.get("resetToken") or "", "reset")
    except jwt.PyJWTError: return err("Reset session expired. Start again.", 401)
    pw = d.get("password") or ""
    if (m := pw_problem(pw)): return err(m)
    if pw != d.get("confirmPassword"): return err("Passwords do not match")
    db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(pw), p["sub"]))
    db().execute("INSERT OR IGNORE INTO revoked VALUES(?,?)", (p["jti"], p["exp"])); db().commit()
    audit("password_reset", "", int(p["sub"]))
    return jsonify(ok=True)

@app.post("/api/auth/signout")
@auth_required
def signout():
    db().execute("INSERT OR IGNORE INTO revoked VALUES(?,?)", (g.claims["jti"], g.claims["exp"]))
    db().execute("DELETE FROM revoked WHERE exp < ?", (int(time.time()),)); db().commit()
    audit("signout", "", g.user["id"])
    return jsonify(ok=True)

@app.get("/api/me")
@auth_required
def me():
    return jsonify(user=public_user(g.user))

# ---------- dashboard ----------
def ago(ts):
    s = int(time.time()) - ts
    return "just now" if s < 60 else f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago" if s < 86400 else f"{s // 86400} d ago"

def sev(sc):
    return "critical" if sc >= 80 else "high" if sc >= 60 else "medium" if sc >= 40 else "low"

def inc_json(r):
    return {"severity": sev(r["score"]), "id": r["id"], "title": r["title"], "employee": r["employee"], "department": r["dept"], "score": r["score"],
            "status": r["status"], "detected": ago(r["detected_at"]), "path": [r["source"], r["host"], r["dest"]],
            "size": r["size"], "files": r["files"]}

@app.get("/api/dashboard")
@auth_required
def dashboard():
    rows = db().execute("SELECT * FROM incidents ORDER BY detected_at DESC").fetchall()
    open_ = [r for r in rows if r["status"] in ("open", "investigating")]
    active = max(open_, key=lambda r: r["score"], default=None)
    return jsonify(
        user=public_user(g.user),
        stats={"openAlerts": len(open_), "critical": sum(r["score"] >= 80 for r in open_), "endpoints": 1284, "online": 1279,
               "eventsPerMinute": 48000 + random.randint(0, 500), "status": "Protected"},
        activeIncident=inc_json(active) if active else None,
        recent=[inc_json(r) for r in rows[:6]],
        channels=[{"channel": "Cloud storage", "volume": "212 GB", "flagged": 3, "status": "Critical"},
                  {"channel": "USB / removable", "volume": "38 GB", "flagged": 2, "status": "Review"},
                  {"channel": "Email", "volume": "14 GB", "flagged": 1, "status": "Review"},
                  {"channel": "Print and screenshots", "volume": "1.2 GB", "flagged": 0, "status": "Normal"}])

STATUSES = ("open", "investigating", "blocked", "resolved", "false_positive")

@app.get("/api/incidents")
@auth_required
def incidents():
    rows = db().execute("SELECT * FROM incidents ORDER BY detected_at DESC").fetchall()
    counts = {"all": len(rows), **{k: sum(r["status"] == k for r in rows) for k in STATUSES}}
    st, sv = request.args.get("status", ""), request.args.get("severity", "")
    q = request.args.get("q", "").strip().lower()[:80]
    out = [r for r in rows if (not st or r["status"] == st) and (not sv or sev(r["score"]) == sv)
           and (not q or q in " ".join(str(r[k]) for k in ("id", "title", "employee", "dept", "host", "dest", "source")).lower())]
    return jsonify(incidents=[inc_json(r) for r in out], counts=counts)

@app.get("/api/incidents/<iid>")
@auth_required
def incident_detail(iid):
    r = db().execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not r: return err("Incident not found", 404)
    h = db().execute("SELECT a.ts, a.action, u.name FROM audit a LEFT JOIN users u ON u.id=a.user_id "
                     "WHERE a.detail=? AND a.action LIKE 'incident_%' ORDER BY a.id DESC LIMIT 20", (iid,)).fetchall()
    return jsonify(incident=inc_json(r), history=[{"time": ago(x["ts"]), "action": x["action"][9:], "by": x["name"] or "System"} for x in h])

ACTIONS = {"block": ("blocked", "Upload blocked and session isolated"), "open": ("investigating", "Incident opened"),
           "safe": ("false_positive", "Marked as false positive"),
           "resolve": ("resolved", "Incident resolved"), "reopen": ("open", "Incident reopened")}

@app.post("/api/incidents/<iid>/action")
@auth_required
def incident_action(iid):
    a = body().get("action")
    if a not in ACTIONS: return err("Unknown action")
    if not db().execute("SELECT 1 FROM incidents WHERE id=?", (iid,)).fetchone(): return err("Incident not found", 404)
    db().execute("UPDATE incidents SET status=? WHERE id=?", (ACTIONS[a][0], iid)); db().commit()
    audit(f"incident_{a}", iid, g.user["id"])
    if a == "block":  # isolate the device the transfer came from
        inc = db().execute("SELECT host FROM incidents WHERE id=?", (iid,)).fetchone()
        if db().execute("UPDATE endpoints SET status='isolated' WHERE host=? AND status='online'", (inc["host"],)).rowcount:
            hlog("endpoint", "Device isolated", inc["host"])
        db().commit()
    hlog("alert", ACTIONS[a][1], iid)
    return jsonify(ok=True, status=ACTIONS[a][0], message=ACTIONS[a][1])

LATEST_AGENT = "5.2.1"
RISKY = ("drive.google.com","dropbox.com","wetransfer.com","mega.nz","mega.io","onedrive.live.com","box.com","icloud.com",
         "transfer.sh","sendspace.com","file.io","pastebin.com","mediafire.com")
ALLOWED = [d.strip().lower() for d in os.environ.get("ALLOWED_DOMAINS", "").split(",") if d.strip()]

def dom_in(host, lst):
    return any(host == d or host.endswith("." + d) for d in lst)

def fmt_size(n):
    for u, d in (("GB", 2**30), ("MB", 2**20), ("KB", 2**10)):
        if n >= d: return f"{n / d:.1f} {u}"
    return f"{n} B"

@app.get("/api/bootstrap")
@auth_required
def bootstrap():
    d, now = db(), int(time.time())
    return jsonify(
        alerts=[{"id": r["id"], "title": r["title"], "emp": r["employee"], "dept": r["dept"], "score": r["score"], "st": r["status"],
                 "ts": r["detected_at"] * 1000, "path": [r["source"], r["host"], r["dest"]], "size": r["size"], "files": r["files"]}
                for r in d.execute("SELECT * FROM incidents ORDER BY detected_at DESC")],
        employees=[{"name": r["name"], "dept": r["dept"], "role": r["role"], "risk": r["risk"], "gb": r["gb"], "st": r["status"]}
                   for r in d.execute("SELECT * FROM employees ORDER BY risk DESC")],
        endpoints=[{"host": r["host"], "user": r["usr"], "dept": r["dept"], "os": r["os"], "osv": r["osv"], "ip": r["ip"], "agent": r["agent"],
                    "st": r["status"], "seen": max(0, (now - r["last_seen"]) // 60) if r["status"] == "offline" else 0,
                    "risk": r["risk"], "out": r["out_gb"], "usb": r["usb"], "ub": r["usb_blocked"]}
                   for r in d.execute("SELECT * FROM endpoints ORDER BY risk DESC")],
        history=[{"ts": r["ts"] * 1000, "by": r["actor"], "cat": r["cat"], "text": r["text"], "ref": r["ref"]}
                 for r in d.execute("SELECT * FROM history ORDER BY ts DESC, id DESC LIMIT 300")])

@app.post("/api/employees/<name>/action")
@auth_required
def employee_action(name):
    a = body().get("action"); r = db().execute("SELECT * FROM employees WHERE name=?", (name,)).fetchone()
    if not r: return err("Employee not found", 404)
    st = r["status"]
    if a == "watch": st = "active" if st == "watchlist" else "watchlist"; m = "Added to watchlist" if st == "watchlist" else "Removed from watchlist"
    elif a == "susp": st = "active" if st == "suspended" else "suspended"; m = "Access suspended" if st == "suspended" else "Access restored"
    elif a == "remind": m = "Policy reminder sent"
    else: return err("Unknown action")
    db().execute("UPDATE employees SET status=? WHERE name=?", (st, name)); db().commit()
    hlog("employee", m, name)
    return jsonify(ok=True, message=m)

@app.post("/api/endpoints/<host>/action")
@auth_required
def endpoint_action(host):
    a = body().get("action"); r = db().execute("SELECT * FROM endpoints WHERE host=?", (host,)).fetchone()
    if not r: return err("Endpoint not found", 404)
    if a in ("iso", "scan") and r["status"] == "offline": return err("Device is offline")
    if a == "iso":
        st = "online" if r["status"] == "isolated" else "isolated"
        db().execute("UPDATE endpoints SET status=? WHERE host=?", (st, host)); m = "Device isolated" if st == "isolated" else "Network access restored"
    elif a == "scan": m = "Scan started"
    elif a == "usb":
        v = 0 if r["usb_blocked"] else 1
        db().execute("UPDATE endpoints SET usb_blocked=? WHERE host=?", (v, host)); m = "USB storage blocked" if v else "USB storage allowed"
    elif a == "upd":
        db().execute("UPDATE endpoints SET agent=? WHERE host=?", (LATEST_AGENT, host)); m = "Agent updated to " + LATEST_AGENT
    else: return err("Unknown action")
    db().commit(); hlog("endpoint", m, host)
    return jsonify(ok=True, message=m)

@app.post("/api/events")
@auth_required
def events():
    """Reports from the browser extension: the signed-in user is uploading files to a website (names + sizes only)."""
    d = body(); domain = str(d.get("domain") or "").lower()[:100]
    files = [f for f in (d.get("files") if isinstance(d.get("files"), list) else []) if isinstance(f, dict)][:500]
    if d.get("kind") != "upload" or not re.fullmatch(r"[a-z0-9.-]+", domain) or not files: return err("Invalid event")
    if dom_in(domain, ALLOWED): return jsonify(recorded=False, reason="allowed domain")
    if limited(f"ev:{g.user['id']}", 30, 60): return err("Too many events", 429)
    def sz(f):
        try: return max(0, int(f.get("size") or 0))
        except (TypeError, ValueError): return 0
    n, total = len(files), sum(sz(f) for f in files)
    score = min(99, (70 if dom_in(domain, RISKY) else 40) + min(20, n * 2) + min(10, total // (100 * 2**20)))
    me, now = g.user["name"], int(time.time())
    row = db().execute("SELECT * FROM incidents WHERE employee=? AND dest=? AND status='open' AND detected_at>? ORDER BY detected_at DESC",
                       (me, domain, now - 120)).fetchone()
    if row:  # same burst: merge into the existing alert
        db().execute("UPDATE incidents SET files=files+?, score=MAX(score,?) WHERE id=?", (n, score, row["id"])); db().commit()
        return jsonify(recorded=True, id=row["id"], score=max(row["score"], score), merged=True)
    nxt = (db().execute("SELECT MAX(CAST(SUBSTR(id,5) AS INTEGER)) m FROM incidents").fetchone()["m"] or 2000) + 1
    iid = f"INC-{nxt}"; title = ("Bulk upload to " if n >= 5 else "File upload to ") + domain
    db().execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                 (iid, title, me, "Browser", score, "open", now, "Local files", "Browser extension", domain, fmt_size(total), n))
    db().commit(); hlog("alert", "Alert raised: " + title, iid, "Myphema extension")
    return jsonify(recorded=True, id=iid, score=score)

@app.get("/api/audit")
@auth_required
def audit_log():
    rows = db().execute("SELECT ts,action,detail FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 50", (g.user["id"],)).fetchall()
    return jsonify(entries=[dict(r) for r in rows])

@app.get("/api/health")
def health():
    return jsonify(ok=True)

@app.get("/app.js")
def appjs():
    return send_from_directory(app.static_folder, "app.js")

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.errorhandler(404)
def nf(_): return err("Not found", 404)
@app.errorhandler(405)
def na(_): return err("Method not allowed", 405)
@app.errorhandler(413)
def big(_): return err("Request too large", 413)

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
