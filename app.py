from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify, send_file
import sqlite3, os, re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "messenger.db")
UPLOAD_FOLDER = os.path.join(APP_DIR, "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'doc', 'docx'}

# Define admin username
ADMIN_USERNAME = "Admin"

active_users = {}

OFFLINE_THRESHOLD = timedelta(minutes=2)

FORBIDDEN_USERNAMES = [ 'admin', 'owner', 'moderator', 'sysadmin', 'adm', 'admi', 'admn' ]  # Lowercase forbidden names, add variations as needed

def admin_exists():
    db = get_db()
    r = db.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    return r is not None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_request
def update_activity():
    if "username" in session:
        active_users[session["username"]] = datetime.now()

def get_user_status(username):
    now = datetime.now()
    if username in active_users:
        last_seen = active_users[username]
        if now - last_seen < OFFLINE_THRESHOLD:
            return "online"
        else:
            return f"last seen {last_seen.strftime('%H:%M')}"
    return "offline"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, last_seen TEXT, is_admin INTEGER DEFAULT 0, is_blocked INTEGER DEFAULT 0, block_until TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, receiver_id INTEGER NOT NULL, message TEXT, file_path TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)')
    db.commit()
    # Delete forbidden usernames except Admin
    forbidden = ','.join('?' for _ in FORBIDDEN_USERNAMES)
    db.execute(f"DELETE FROM users WHERE lower(username) IN ({forbidden}) AND username != ?", [*FORBIDDEN_USERNAMES, ADMIN_USERNAME])
    db.commit()

_pw_re = re.compile(r'^[\x21-\x7E]{5,30}$')
_user_re = re.compile(r'^[A-Za-z]{5,10}$')

def validate_registration(username, password):
    if not _user_re.fullmatch(username):
        return False, "Имя должно быть 5-10 английских букв (A-Z)."
    if not _pw_re.fullmatch(password):
        return False, "Пароль должен быть 5-30 печатных ASCII символов (без пробелов и эмодзи)."
    weak = {"12345","password","qwerty","admin","letmein","11111","123456","password1"}
    if password.lower() in weak:
        return False, "Пароль слишком простой."
    if not re.search(r'[A-Za-z]', password) or not re.search(r'[\d!@#$%^&*()_+\-=\[\]{};:\\|,.<>\/?]', password):
        return False, "Пароль должен содержать буквы и хотя бы одну цифру или символ."
    lower_username = username.lower()
    if lower_username in FORBIDDEN_USERNAMES and username != ADMIN_USERNAME:
        return False, "Имя запрещено."
    if not admin_exists() and username != ADMIN_USERNAME:
        return False, "Регистрация доступна только для Admin."
    return True, None

def create_user(username, password):
    db = get_db()
    try:
        hashed = generate_password_hash(password)
        is_admin = 1 if username == ADMIN_USERNAME else 0
        cur = db.execute("INSERT INTO users (username, password, last_seen, is_admin) VALUES (?, ?, ?, ?)", (username, hashed, None, is_admin))
        db.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None

def find_users(q, exclude_username=None, limit=50):
    db = get_db()
    qlike = f"%{q}%"
    rows = db.execute("SELECT id, username, last_seen, is_blocked, block_until FROM users WHERE username LIKE ? ORDER BY username LIMIT ?", (qlike, limit)).fetchall()
    res = []
    for r in rows:
        if r["username"] == exclude_username:
            continue
        res.append((r["id"], r["username"], r["last_seen"], r["is_blocked"], r["block_until"]))
    return res

def save_message(sender_id, receiver_id, message, file_path=None):
    db = get_db()
    timestamp = datetime.utcnow().isoformat() + 'Z'
    db.execute("INSERT INTO messages (sender_id, receiver_id, message, file_path, timestamp) VALUES (?, ?, ?, ?, ?)",
               (sender_id, receiver_id, message, file_path, timestamp))
    db.commit()

def get_history(a, b):
    db = get_db()
    rows = db.execute("SELECT id, sender_id, message, file_path, timestamp FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY id ASC", (a, b, b, a)).fetchall()
    return [{"id": r["id"], "sender_id": r["sender_id"], "message": r["message"], "file_path": r["file_path"], "timestamp": r["timestamp"]} for r in rows]

def get_chat_list(user_id):
    db = get_db()
    rows = db.execute("SELECT sender_id, receiver_id, message, timestamp FROM messages WHERE sender_id = ? OR receiver_id = ? ORDER BY id DESC", (user_id, user_id)).fetchall()
    seen = set()
    chats = []
    for r in rows:
        s = r["sender_id"]; rec = r["receiver_id"]
        partner = rec if s == user_id else s
        if partner in seen:
            continue
        seen.add(partner)
        u = db.execute("SELECT username, last_seen FROM users WHERE id = ?", (partner,)).fetchone()
        uname = u["username"] if u else "Unknown"
        last_seen = u["last_seen"] if u else None
        chats.append({"id": partner, "username": uname, "last_message": r["message"] or "", "time": r["timestamp"] or "", "last_seen": last_seen})
    return chats

@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    return render_template("chat.html", username=username, get_user_status=get_user_status)

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    chats = get_chat_list(session["user_id"])
    return render_template("chat.html", chats=chats, username=session.get("username"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        ok, msg = validate_registration(username, password)
        if not ok:
            return render_template("register.html", error=msg)
        uid = create_user(username, password)
        if uid is None:
            return render_template("register.html", error="Имя уже занято")
        session["user_id"] = uid
        session["username"] = username
        session["is_admin"] = 1 if username == ADMIN_USERNAME else 0
        db = get_db()
        db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (datetime.utcnow().isoformat() + 'Z', uid))
        db.commit()
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        db = get_db()
        r = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if r and check_password_hash(r["password"], password):
            if r["is_blocked"]:
                if r["block_until"] is None:
                    return render_template("login.html", error="Аккаунт заблокирован навсегда")
                else:
                    try:
                        block_until = datetime.fromisoformat(r["block_until"].replace('Z', ''))
                        if datetime.utcnow() < block_until:
                            return render_template("login.html", error=f"Аккаунт заблокирован до {block_until.strftime('%Y-%m-%d %H:%M:%S')}")
                        else:
                            db.execute("UPDATE users SET is_blocked = 0, block_until = NULL WHERE id = ?", (r["id"],))
                            db.commit()
                    except ValueError:
                        pass  # Invalid date, ignore
            session["user_id"] = r["id"]
            session["username"] = username
            session["is_admin"] = r["is_admin"]
            db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (datetime.utcnow().isoformat() + 'Z', r["id"]))
            db.commit()
            return redirect(url_for("index"))
        return render_template("login.html", error="Неверные данные")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if "user_id" in session and "username" in session:
        active_users.pop(session["username"], None)
        db = get_db()
        db.execute("UPDATE users SET last_seen = NULL WHERE id = ?", (session["user_id"],))
        db.commit()
    session.clear()
    return redirect(url_for("login"))

@app.route("/ping", methods=["POST"])
def ping():
    if "user_id" not in session:
        return jsonify({"ok": False}), 403
    db = get_db()
    db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (datetime.utcnow().isoformat() + 'Z', session["user_id"]))
    db.commit()
    return jsonify({"ok": True})

@app.route("/search_user", methods=["POST"])
def search_user():
    data = request.get_json() or {}
    q = data.get("query","").strip()
    rows = find_users(q, exclude_username=session.get("username"))
    return jsonify(rows)

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if 'file' not in request.files:
        return jsonify({"ok": False, "error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"ok": False, "error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        receiver_id = int(request.form.get("receiver_id"))
        message = request.form.get("message", "").strip()
        save_message(session["user_id"], receiver_id, message, unique_filename)
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "File type not allowed"}), 400

@app.route("/download_file/<int:message_id>")
def download_file(message_id):
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    db = get_db()
    row = db.execute("SELECT file_path FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row or not row["file_path"]:
        return jsonify({"ok": False, "error": "File not found"}), 404
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], row["file_path"])
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({"ok": False, "error": "File not found on server"}), 404

@app.route("/send_message", methods=["POST"])
def send_message():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    data = request.get_json() or {}
    receiver_id = int(data.get("receiver_id"))
    message = data.get("message","").strip()
    if not message:
        return jsonify({"ok": False, "error": "Empty message"}), 400
    save_message(session["user_id"], receiver_id, message)
    return jsonify({"ok": True})

@app.route("/get_messages/<int:other_id>")
def get_messages(other_id):
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    rows = get_history(session["user_id"], other_id)
    return jsonify(rows)

@app.route("/chats")
def chats():
    if "user_id" not in session:
        return jsonify([])
    return jsonify(get_chat_list(session["user_id"]))

@app.route("/get_user_status/<int:user_id>")
def get_user_status_by_id(user_id):
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    status = get_user_status(user["username"])
    return jsonify({"ok": True, "status": status})

@app.route("/admin", methods=["GET","POST"])
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    db = get_db()
    error = None
    users = []
    if request.method == "POST":
        q = request.form.get("query","").strip()
        users = find_users(q)
    all_users = db.execute("SELECT id, username FROM users WHERE is_admin = 0 ORDER BY username").fetchall()
    stats = {
        "total_users": len(all_users),
        "total_messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    }
    return render_template("admin.html", users=users, all_users=all_users, stats=stats, error=error)

@app.route("/admin/user/<int:user_id>", methods=["GET","POST"])
def admin_user(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    db = get_db()
    user = db.execute("SELECT username, is_blocked, block_until FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect(url_for("admin"))
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "block":
            permanent = request.form.get("permanent")
            duration = request.form.get("duration")
            if permanent:
                db.execute("UPDATE users SET is_blocked = 1, block_until = NULL WHERE id = ?", (user_id,))
            else:
                block_until = (datetime.utcnow() + timedelta(hours=int(duration))).isoformat() + 'Z'
                db.execute("UPDATE users SET is_blocked = 1, block_until = ? WHERE id = ?", (block_until, user_id))
            db.commit()
            error = "Пользователь заблокирован"
        elif action == "unblock":
            db.execute("UPDATE users SET is_blocked = 0, block_until = NULL WHERE id = ?", (user_id,))
            db.commit()
            error = "Пользователь разблокирован"
        elif action == "change_name":
            new_name = request.form.get("new_name").strip()
            try:
                db.execute("UPDATE users SET username = ? WHERE id = ?", (new_name, user_id))
                db.commit()
                error = "Имя изменено"
            except sqlite3.IntegrityError:
                error = "Имя уже занято"
        elif action == "delete":
            db.execute("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            return redirect(url_for("admin"))
    return render_template("admin_user.html", user_id=user_id, username=user["username"], error=error, is_blocked=user["is_blocked"], block_until=user["block_until"])

@app.route("/admin/user/<int:user_id>/chats")
def admin_user_chats(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect(url_for("admin"))
    chats = get_chat_list(user_id)
    return render_template("admin_user_chats.html", user_id=user_id, username=user["username"], chats=chats)

@app.route("/admin/user/<int:user_id>/chat/<int:partner_id>")
def admin_conversation(user_id, partner_id):
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    partner = db.execute("SELECT username FROM users WHERE id = ?", (partner_id,)).fetchone()
    if not user or not partner:
        return redirect(url_for("admin"))
    messages = get_history(user_id, partner_id)
    return render_template("admin_conversation.html", user_id=user_id, partner_id=partner_id, username=user["username"], partner_name=partner["username"], messages=messages)

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)