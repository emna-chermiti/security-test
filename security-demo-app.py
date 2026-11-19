#!/usr/bin/env python3
"""
TechNest - a minimal e-commerce demo for a university network-security class.

Two modes, selected by a CLI flag or the MODE environment variable:

    python security-demo-app.py --vulnerable   # HTTP  :5000 - SQLi, plaintext passwords
    python security-demo-app.py --secure       # HTTPS :5001 - parameterized SQL, hashed passwords

Each mode uses its own SQLite file and reseeds it on startup, so both apps can
run at the same time and every demo run starts from the same state.

This is classroom demo code, NOT production software. See README.md.
"""

import argparse
import html
import os
import sqlite3

from flask import Flask, g, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash


# ---------------------------------------------------------------------------
# Mode selection: CLI flag (--secure / --vulnerable) or MODE env var
# ---------------------------------------------------------------------------
def pick_mode() -> str:
    parser = argparse.ArgumentParser(description="TechNest security demo")
    parser.add_argument("--vulnerable", action="store_true",
                        help="HTTP :5000 - SQL injection + plaintext passwords")
    parser.add_argument("--secure", action="store_true",
                        help="HTTPS :5001 - parameterized SQL + hashed passwords")
    args, _ = parser.parse_known_args()  # ignore any extra args

    if args.secure:
        return "secure"
    if args.vulnerable:
        return "vulnerable"
    return os.getenv("MODE", "vulnerable").strip().lower()


MODE = pick_mode()
SECURE = MODE == "secure"
PORT = 5001 if SECURE else 5000
SCHEME = "https" if SECURE else "http"
DB_PATH = "store_secure.db" if SECURE else "store_vulnerable.db"
HASH_METHOD = "pbkdf2:sha256"  # portable, works on every platform

app = Flask(__name__)
app.secret_key = "classroom-demo-only-not-a-real-secret"
app.config["SESSION_COOKIE_HTTPONLY"] = True


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
PRODUCTS = [
    ("Laptop Pro", 999.99, "14-inch, 16 GB RAM, 512 GB SSD", "💻"),
    ("Wireless Mouse", 29.99, "Ergonomic, 2000 DPI, silent clicks", "🖱️"),
    ("Mechanical Keyboard", 89.99, "RGB backlight, blue switches", "⌨️"),
    ("4K Monitor", 449.99, "27-inch UHD, 60 Hz, slim bezel", "🖥️"),
    ("USB-C Hub", 39.99, "7-in-1: HDMI, USB 3.0, SD reader", "🔌"),
]

DEMO_ACCOUNTS = [
    ("admin", "admin123", "Administrator"),
    ("alice", "alice123", "Customer"),
    ("bob", "123456", "Customer · weak password"),
]

# Word, PowerPoint and some phone keyboards silently replace straight quotes
# and dashes with typographic look-alikes (' -> ’, -- -> —). When the demo
# payload is copied from a slide, those characters stop it from being SQL.
# We normalize them back to ASCII in VULNERABLE mode only, so the classroom
# demo works. This does NOT make the app safe: the input is still pasted
# straight into the SQL string below.
TYPOGRAPHIC_FIXES = str.maketrans({
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",  # curly single quotes
    "\u201c": '"', "\u201d": '"',                                  # curly double quotes
    "\u00b4": "'", "\u0060": "'", "\u2032": "'",                  # acute, backtick, prime
    "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-",   # en/em dash, minus sign
})


def normalize_demo_input(value: str) -> str:
    """Turn typographic quotes/dashes into ASCII (vulnerable demo only)."""
    return value.translate(TYPOGRAPHIC_FIXES)


def get_db() -> sqlite3.Connection:
    """One SQLite connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Recreate and seed the database. Runs once at startup."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            price       REAL NOT NULL,
            description TEXT,
            icon        TEXT
        );
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        """
    )

    db.executemany(
        "INSERT INTO products (name, price, description, icon) VALUES (?, ?, ?, ?)",
        PRODUCTS,
    )

    if SECURE:
        # SECURE: store only password hashes
        users = [
            (name, generate_password_hash(pw, method=HASH_METHOD), 1 if name == "admin" else 0)
            for name, pw, _role in DEMO_ACCOUNTS
        ]
    else:
        # VULNERABLE: store plaintext passwords
        users = [
            (name, pw, 1 if name == "admin" else 0)
            for name, pw, _role in DEMO_ACCOUNTS
        ]

    db.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        users,
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Shared page layout (single source of CSS so every page looks consistent)
# ---------------------------------------------------------------------------
BASE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · TechNest</title>
<style>
  :root{
    --bg:#eef2f7; --card:#ffffff; --ink:#0f172a; --muted:#64748b;
    --line:#e2e8f0; --accent:#4f46e5; --accent-2:#4338ca;
    --radius:16px; --shadow:0 1px 2px rgba(15,23,42,.05), 0 10px 30px rgba(15,23,42,.07);
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);
       font-family:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;line-height:1.5}
  a{color:var(--accent)}
  h1,h2,h3{line-height:1.2;margin:0 0 10px}
  .muted{color:var(--muted)}
  .wrap{width:100%;max-width:1060px;margin:0 auto;padding:0 20px}

  /* mode banner */
  .mode-strip{padding:8px 16px;text-align:center;font-size:13px;font-weight:700;letter-spacing:.2px}
  .mode-strip.danger{background:#b91c1c;color:#fff}
  .mode-strip.ok{background:#15803d;color:#fff}

  /* header / nav */
  header{background:#0f172a;color:#fff;position:sticky;top:0;z-index:10}
  .header-inner{display:flex;align-items:center;justify-content:space-between;height:64px;gap:16px}
  .brand{display:flex;align-items:center;gap:8px;color:#fff;text-decoration:none;font-weight:800;font-size:19px}
  .brand em{font-style:normal;font-weight:500;font-size:12px;color:#94a3b8;margin-left:2px}
  nav{display:flex;align-items:center;gap:4px;flex-wrap:wrap}
  nav a{color:#cbd5e1;text-decoration:none;font-size:14px;font-weight:600;padding:8px 12px;border-radius:10px}
  nav a:hover{background:rgba(255,255,255,.08);color:#fff}
  nav .nav-cta{background:var(--accent);color:#fff}
  nav .nav-cta:hover{background:var(--accent-2)}
  nav .who{color:#94a3b8;font-size:13px;padding:0 8px}

  main{flex:1;padding-top:28px;padding-bottom:44px}
  footer{border-top:1px solid var(--line);background:#fff;padding:16px 0;margin-top:auto}
  footer .wrap{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--muted)}

  /* cards & buttons */
  .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
  .btn{display:inline-block;border:1px solid var(--line);background:#fff;color:var(--ink);
       padding:10px 16px;border-radius:11px;font-size:14px;font-weight:700;cursor:pointer;
       text-decoration:none;text-align:center}
  .btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
  .btn.primary:hover{background:var(--accent-2)}
  .btn.ghost{background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.35);color:#fff}
  .btn.small{padding:7px 12px;font-size:12.5px;border-radius:9px}

  /* storefront */
  .hero{display:grid;grid-template-columns:1.4fr .6fr;gap:20px;align-items:center;
        background:linear-gradient(135deg,#1e1b4b,#312e81 55%,#4f46e5);color:#fff;
        border-radius:22px;padding:36px;margin-bottom:28px;box-shadow:var(--shadow)}
  .hero h1{font-size:38px;margin:10px 0 12px}
  .hero p{color:#c7d2fe;margin:0 0 22px;max-width:46ch}
  .hero-art{font-size:96px;text-align:center;filter:drop-shadow(0 12px 24px rgba(0,0,0,.35))}
  .pill{display:inline-block;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);
        padding:4px 10px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.12em}
  .hero-actions{display:flex;gap:10px;flex-wrap:wrap}
  .section-title{font-size:20px;margin:26px 0 14px}

  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:16px}
  .product{background:#fff;border:1px solid var(--line);border-radius:var(--radius);
           padding:18px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:6px}
  .product-icon{font-size:38px}
  .product h3{font-size:16px;margin:2px 0 0}
  .product .muted{font-size:13px;flex:1;margin:0}
  .product-foot{display:flex;align-items:center;justify-content:space-between;margin-top:10px;gap:8px}
  .price{font-weight:800;font-size:17px;color:var(--accent)}

  /* login */
  .auth-wrap{display:flex;justify-content:center;padding:10px 0 30px}
  .auth-card{width:100%;max-width:440px;padding:30px}
  .auth-head{text-align:center;margin-bottom:18px}
  .auth-logo{font-size:38px}
  .auth-head h1{font-size:24px;margin:8px 0 4px}
  .form label{display:block;font-size:13px;font-weight:700;color:#334155;margin-bottom:14px}
  .form input{width:100%;margin-top:6px;padding:11px 12px;border:1px solid #cbd5e1;
              border-radius:11px;font-size:14px;background:#f8fafc}
  .form input:focus{outline:2px solid #c7d2fe;border-color:var(--accent);background:#fff}
  .form .btn{width:100%;margin-top:4px}
  .divider{height:1px;background:var(--line);margin:22px 0}
  .cred-box h3{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 8px}

  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);text-align:left}
  th,td{padding:8px 10px;border-bottom:1px solid var(--line)}
  tr:last-child td{border-bottom:none}

  code{background:#0f172a;color:#e2e8f0;padding:2px 7px;border-radius:7px;
       font-family:Consolas,"Courier New",monospace;font-size:12.5px}
  .payload{display:inline-block;margin-top:8px;padding:9px 12px;font-size:13.5px;
           background:#450a0a;color:#fecaca;border:1px solid #7f1d1d}

  .alert{padding:11px 14px;border-radius:11px;font-size:13.5px;font-weight:600;margin-bottom:16px}
  .alert.danger{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
  .alert.ok{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}

  .hint{border-radius:12px;padding:14px 16px;font-size:13.5px;margin-top:18px;border:1px dashed}
  .hint p{margin:6px 0 0}
  .hint.danger{background:#fff7f7;border-color:#fca5a5}
  .hint.ok{background:#f7fdf9;border-color:#86efac}

  /* dashboard */
  .welcome{background:linear-gradient(135deg,#065f46,#047857);color:#fff;border-radius:22px;
           padding:30px 34px;box-shadow:var(--shadow);margin-bottom:8px}
  .welcome h1{font-size:30px;margin:0 0 6px}
  .welcome p{color:#a7f3d0;margin:0}
  .badge{display:inline-block;background:rgba(255,255,255,.18);padding:2px 10px;border-radius:999px;
         font-size:12px;font-weight:800;letter-spacing:.04em}

  /* admin */
  .admin-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:18px}
  .stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px}
  .stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:var(--shadow)}
  .stat b{display:block;font-size:24px}
  .stat span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
  .panel{background:#fff;border:1px solid var(--line);border-radius:var(--radius);
         box-shadow:var(--shadow);padding:22px;margin-bottom:20px}
  .panel h2{font-size:17px;margin:0 0 12px}
  .tag{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.04em}
  .tag.red{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca}
  .tag.green{background:#f0fdf4;color:#15803d;border:1px solid #bbf7d0}
  .notice{background:#fffbeb;border:1px solid #fde68a;color:#92400e;border-radius:12px;
          padding:12px 16px;font-size:13.5px;margin-bottom:20px}

  @media(max-width:720px){
    .hero{grid-template-columns:1fr;padding:26px}
    .hero-art{display:none}
    .hero h1{font-size:30px}
  }
</style>
</head>
<body>

<div class="mode-strip {{ 'ok' if secure else 'danger' }}">
  {% if secure %}🔒 SECURE MODE{% else %}⚠️ VULNERABLE MODE{% endif %}
  · {{ scheme|upper }}://127.0.0.1:{{ port }} ·
  {% if secure %}PBKDF2-hashed passwords · parameterized SQL{% else %}plaintext passwords · raw SQL concatenation{% endif %}
</div>

<header>
  <div class="wrap header-inner">
    <a class="brand" href="/">🛒 <span>TechNest</span><em>demo store</em></a>
    <nav>
      <a href="/">Store</a>
      <a href="/dashboard">Dashboard</a>
      {% if user %}
        <span class="who">👤 {{ user }}</span>
        <a class="nav-cta" href="/logout">Logout</a>
      {% else %}
        <a class="nav-cta" href="/login">Login</a>
      {% endif %}
    </nav>
  </div>
</header>

<main class="wrap">{{ content|safe }}</main>

<footer>
  <div class="wrap">
    <span>TechNest demo · {{ 'HTTPS' if secure else 'HTTP' }} · port {{ port }} · for classroom use only</span>
    <span>Other mode:
      <a href="http://127.0.0.1:5000/login">vulnerable :5000</a> ·
      <a href="https://127.0.0.1:5001/login">secure :5001</a>
    </span>
  </div>
</footer>

</body>
</html>
"""


def render_page(content: str, title: str = "Store"):
    """Wrap page content in the shared layout."""
    return render_template_string(
        BASE,
        title=title,
        content=content,
        secure=SECURE,
        scheme=SCHEME,
        port=PORT,
        user=session.get("user"),
    )


def product_grid(rows):
    """Render product cards from database rows."""
    cards = []
    for p in rows:
        cards.append(
            f"""
            <article class="product">
              <div class="product-icon">{p['icon']}</div>
              <h3>{html.escape(p['name'])}</h3>
              <p class="muted">{html.escape(p['description'])}</p>
              <div class="product-foot">
                <span class="price">${p['price']:.2f}</span>
                <button class="btn small" onclick="alert('Demo store - the cart is not implemented.')">Add to cart</button>
              </div>
            </article>
            """
        )
    return f'<div class="grid">{"".join(cards)}</div>'


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def store():
    """Public storefront - gives the projector something nice to look at."""
    rows = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    hero = f"""
    <section class="hero">
      <div>
        <span class="pill">{'SECURE' if SECURE else 'VULNERABLE'} DEMO</span>
        <h1>Everyday tech,<br>demo-store prices.</h1>
        <p>A tiny Flask + SQLite shop used to demonstrate network attacks and
           defenses. Sign in, poke at it, then break it.</p>
        <div class="hero-actions">
          <a class="btn primary" href="/login">Sign in to shop</a>
          <a class="btn ghost" href="/dashboard">Go to dashboard</a>
        </div>
      </div>
      <div class="hero-art">🛒</div>
    </section>
    """
    content = hero + '<h2 class="section-title">Featured products</h2>' + product_grid(rows)
    return render_page(content, "Store")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login. Deliberately SQL-injectable in vulnerable mode."""
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        if SECURE:
            # SECURE: parameterized query + hash verification
            row = db.execute(
                "SELECT username, password, is_admin FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row and check_password_hash(row["password"], password):
                session["user"] = row["username"]
                session["is_admin"] = bool(row["is_admin"])
                return redirect("/dashboard")
        else:
            # VULNERABLE: raw string concatenation -> SQL injection
            # Normalize typographic quotes/dashes so payloads pasted from
            # slides still work. The input is still NOT escaped or sanitized.
            username = normalize_demo_input(username)
            password = normalize_demo_input(password)
            query = (
                f"SELECT username, password, is_admin FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            try:
                row = db.execute(query).fetchone()
            except sqlite3.Error as exc:
                print(f"[vulnerable] SQL error: {exc}")
                row = None
            if row:
                session["user"] = row["username"]
                session["is_admin"] = bool(row["is_admin"])
                return redirect("/dashboard")

        error = "Invalid username or password."

    content = login_page(error)
    return render_page(content, "Sign in")


def login_page(error=None):
    error_html = f'<div class="alert danger">⚠️ {html.escape(error)}</div>' if error else ""

    return f"""
    <div class="auth-wrap">
      <div class="card auth-card">
        <div class="auth-head">
          <div class="auth-logo">🛒</div>
          <h1>Sign in</h1>
          <p class="muted">Welcome back to TechNest</p>
        </div>
        {error_html}
        <form class="form" method="POST" action="/login">
          <label>Username
            <input name="username" autocomplete="username" placeholder="e.g. alice" required autofocus>
          </label>
          <label>Password
            <input type="password" name="password" autocomplete="current-password" placeholder="password">
          </label>
          <button class="btn primary" type="submit">Sign in</button>
        </form>
      </div>
    </div>
    """


@app.route("/dashboard")
def dashboard():
    """Logged-in view with the product grid."""
    if "user" not in session:
        return redirect("/login")

    rows = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    name = html.escape(session["user"])
    role = "Administrator" if session.get("is_admin") else "Customer"
    tip = (
        "Passwords in this database are stored as PBKDF2 hashes and the login query is parameterized."
        if SECURE
        else "Passwords in this database are stored in plain text and the login query is concatenated by hand."
    )

    content = f"""
    <section class="welcome">
      <h1>Welcome back, {name}!</h1>
      <p>Signed in as <span class="badge">{role}</span> · {tip}</p>
    </section>
    <h2 class="section-title">Featured products</h2>
    {product_grid(rows)}
    """
    return render_page(content, "Dashboard")


@app.route("/admin")
def admin():
    """
    Admin console used for the ACL / iptables demo.

    Intentionally has NO application-level authorization check. In this demo
    the network ACL (iptables) is the only control protecting this page.
    """
    db = get_db()
    users = db.execute("SELECT id, username, password, is_admin FROM users ORDER BY id").fetchall()
    product_count = db.execute("SELECT COUNT(*) AS n FROM products").fetchone()["n"]

    user_rows = []
    for u in users:
        if SECURE:
            stored = (
                f"<code>{html.escape(u['password'][:44])}…</code> "
                f'<span class="tag green">hashed</span>'
            )
        else:
            stored = (
                f"<code>{html.escape(u['password'])}</code> "
                f'<span class="tag red">PLAINTEXT</span>'
            )
        role = "Administrator" if u["is_admin"] else "Customer"
        user_rows.append(
            f"<tr><td>{u['id']}</td><td><strong>{html.escape(u['username'])}</strong></td>"
            f"<td>{role}</td><td>{stored}</td></tr>"
        )

    content = f"""
    <div class="admin-head">
      <div>
        <h1>Admin console</h1>
        <p class="muted">User and product overview · {SCHEME.upper()} port {PORT}</p>
      </div>
      <span class="tag {'green' if SECURE else 'red'}">
        {'SECURE MODE' if SECURE else 'VULNERABLE MODE'}
      </span>
    </div>

    <div class="stat-row">
      <div class="stat"><b>{len(users)}</b><span>Users</span></div>
      <div class="stat"><b>{product_count}</b><span>Products</span></div>
      <div class="stat"><b>{'HTTPS' if SECURE else 'HTTP'}</b><span>Transport</span></div>
      <div class="stat"><b>{PORT}</b><span>Port</span></div>
    </div>

    <div class="notice">
      <strong>Demo note:</strong> this page has no application-level authorization on
      purpose. The ACL demo protects it with an iptables rule instead — iptables
      matches IP addresses and ports, not URLs.
    </div>

    <div class="panel">
      <h2>Users</h2>
      <table>
        <thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Stored password</th></tr></thead>
        <tbody>{''.join(user_rows)}</tbody>
      </table>
    </div>

    <div class="panel">
      <h2>What this page shows</h2>
      <p class="muted" style="margin:0">
        {'Passwords are stored as one-way PBKDF2 hashes — the original values cannot be read back.'
         if SECURE else
         'Passwords are stored as readable plain text — anyone with database access can read them.'}
      </p>
    </div>
    """
    return render_page(content, "Admin console")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()

    print("=" * 62)
    if SECURE:
        print("  TechNest - SECURE MODE (HTTPS)")
        print(f"  URL      : https://127.0.0.1:{PORT}")
        print("  Database : PBKDF2 password hashes, parameterized SQL")
        print("  TLS      : self-signed certificate (demo only)")
    else:
        print("  TechNest - VULNERABLE MODE (HTTP)")
        print(f"  URL      : http://127.0.0.1:{PORT}")
        print("  Database : plaintext passwords, raw SQL concatenation")
    print(f"  DB file  : {DB_PATH} (reseeded on every start)")
    print("=" * 62)

    if SECURE:
        app.run(host="0.0.0.0", port=PORT, debug=False, ssl_context="adhoc")
    else:
        app.run(host="0.0.0.0", port=PORT, debug=False)