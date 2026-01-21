# forum_server.py — Forum minimal (Flask + SQLAlchemy) avec PostgreSQL ou SQLite fallback
# Dépendances: pip install flask flask_sqlalchemy psycopg2-binary python-dotenv requests
import os, secrets, hashlib, requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=APP_DIR, static_url_path="")

# DB config
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
if not DATABASE_URL:
    # Fallback local (dev): SQLite file
    DATABASE_URL = "sqlite:///" + os.path.join(APP_DIR, "forum.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Models
class Topic(db.Model):
    __tablename__ = "topics"
    id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(db.String(160), nullable=False)
    title = db.Column(db.String(240), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    topic_id = db.Column(db.Integer, db.ForeignKey("topics.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("comments.id", ondelete="CASCADE"), nullable=True, index=True)
    author_name = db.Column(db.String(160), nullable=False)
    body = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(120))
    country = db.Column(db.String(120))
    country_code = db.Column(db.String(8))
    ip_addr = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    edit_token_hash = db.Column(db.String(128))  # sha256

    def can_edit(self, token: str) -> bool:
        if not token or not self.edit_token_hash: return False
        return hashlib.sha256(token.encode("utf-8")).hexdigest() == self.edit_token_hash

with app.app_context():
    db.create_all()

# Helpers
def client_ip():
    # Trust X-Forwarded-For if present
    h = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if h: return h
    return request.remote_addr or "127.0.0.1"

def geo_from_ip(ip: str):
    # Resolve city/country via ipapi.co (best-effort)
    try:
        if ip in ("127.0.0.1", "::1"):
            return {"city":"Local","country":"—","country_code":""}
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if resp.ok:
            j = resp.json()
            return {
                "city": j.get("city") or "",
                "country": j.get("country_name") or "",
                "country_code": (j.get("country_code") or "").upper(),
            }
    except Exception:
        pass
    return {"city":"", "country":"", "country_code":""}

def comment_to_dict(c: Comment):
    return {
        "id": c.id,
        "topic_id": c.topic_id,
        "parent_id": c.parent_id,
        "author_name": c.author_name,
        "body": "[commentaire supprimé]" if c.deleted else c.body,
        "city": c.city, "country": c.country, "country_code": c.country_code,
        "created_at": (c.created_at or datetime.now(timezone.utc)).isoformat(),
        "updated_at": (c.updated_at.isoformat() if c.updated_at else None),
        "deleted": c.deleted,
    }

def topic_to_dict(t: Topic):
    comments = (Comment.query.filter_by(topic_id=t.id)
                .order_by(Comment.parent_id.isnot(None), Comment.created_at.asc())
                .all())
    return {
        "id": t.id,
        "author_name": t.author_name,
        "title": t.title,
        "body": t.body,
        "created_at": (t.created_at or datetime.now(timezone.utc)).isoformat(),
        "comments": [comment_to_dict(c) for c in comments]
    }

# Routes
@app.get("/")
def index():
    return redirect(url_for("static_files", path="forum_de_discussion.html"))

@app.get("/<path:path>")
def static_files(path):
    return send_from_directory(APP_DIR, path)

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/api/forum/topics")
def list_topics():
    items = Topic.query.order_by(Topic.id.desc()).limit(50).all()
    return jsonify({"items": [topic_to_dict(t) for t in items]})

@app.post("/api/forum/topics")
def create_topic():
    data = request.get_json(force=True, silent=True) or {}
    author = (data.get("author_name") or "").strip()
    title  = (data.get("title") or "").strip()
    body   = (data.get("body") or "").strip()
    if not author or not title or not body:
        return jsonify({"error":"Champs requis manquants."}), 400
    t = Topic(author_name=author, title=title, body=body)
    db.session.add(t); db.session.commit()
    return jsonify({"ok": True, "id": t.id})

@app.post("/api/forum/comments")
def create_comment():
    data = request.get_json(force=True, silent=True) or {}
    topic_id = data.get("topic_id")
    parent_id = data.get("parent_id")
    author = (data.get("author_name") or "").strip()
    body   = (data.get("body") or "").strip()
    if not topic_id or not author or not body:
        return jsonify({"error":"Champs requis manquants."}), 400
    # Geo
    ip = client_ip()
    g = geo_from_ip(ip)
    token = secrets.token_urlsafe(16)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    c = Comment(topic_id=topic_id, parent_id=parent_id, author_name=author, body=body,
                city=g["city"], country=g["country"], country_code=g["country_code"], ip_addr=ip,
                edit_token_hash=token_hash)
    db.session.add(c); db.session.commit()
    return jsonify({"ok": True, "comment": comment_to_dict(c), "token": token})

@app.put("/api/forum/comments/<int:cid>")
def update_comment(cid):
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token") or ""
    body  = (data.get("body") or "").strip()
    c = Comment.query.get_or_404(cid)
    if not c.can_edit(token):
        return jsonify({"error":"Non autorisé."}), 403
    if not body:
        return jsonify({"error":"Contenu vide."}), 400
    c.body = body
    c.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True, "comment": comment_to_dict(c)})

@app.delete("/api/forum/comments/<int:cid>")
def delete_comment(cid):
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token") or ""
    c = Comment.query.get_or_404(cid)
    if not c.can_edit(token):
        return jsonify({"error":"Non autorisé."}), 403
    c.deleted = True
    c.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "4000"))
    app.run(host="0.0.0.0", port=port, debug=True)
