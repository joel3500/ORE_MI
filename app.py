from flask import Flask, request, jsonify, abort, Response, send_from_directory, redirect, url_for, render_template, session
from peewee import fn, JOIN, DoesNotExist
from ore_mi_bd import db as peewee_db, init_db, User, EmailVerificationCode, Topic, Comment, Testimonial, TestimonialComment, TestimonialReply, Event

import os, mimetypes, json, time, secrets, hashlib, requests, math, base64, logging
from datetime import datetime, timezone
from typing import Iterable, Generator
from dotenv import load_dotenv

# videos
from werkzeug.utils import secure_filename, safe_join

# Helpers pour le Forum
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.message import EmailMessage
from datetime import timedelta

load_dotenv()

STREAM_DISABLED = (os.getenv("DISABLE_STREAM", "0").lower() in ("1","true","yes"))

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Static servi à la racine: /css/... /js/... /img/...
app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_change_me")

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# Init DB (Postgres -> fallback SQLite)
init_db()

# ----------------- Témoignages (vidéos) - Configuration -----------------
UPLOAD_VIDEO_DIR = os.path.join(APP_DIR, "uploads", "videos")
os.makedirs(UPLOAD_VIDEO_DIR, exist_ok=True)   # dossier public, servi par static_files
ALLOWED_VIDEO_EXTS = {"mp4", "mov", "webm", "m4v", "avi", "ogg" }
MAX_VIDEO_MB = 100   # taille Max de 100 Mo acceptable pour une video.

# -------------------  Dossiers d’upload pour evenements èa venir
EVENT_BASE = os.path.join(APP_DIR, "uploads", "events")
os.makedirs(os.path.join(EVENT_BASE, "images"), exist_ok=True)
os.makedirs(os.path.join(EVENT_BASE, "videos"), exist_ok=True)

ALLOWED_IMG = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
ALLOWED_VID = {".mp4", ".webm", ".mov", ".m4v", ".ogg" }

import mimetypes
# Dossier des uploads
UPLOADS_DIR = os.path.join(APP_DIR, "uploads")

mimetypes.add_type("video/mp4", ".mp4")
mimetypes.add_type("video/webm", ".webm")
mimetypes.add_type("video/mov", ".mov")
mimetypes.add_type("video/m4v", ".m4v") 
mimetypes.add_type("video/ogg", ".ogg")

mimetypes.add_type("image/jpg", ".jpg")
mimetypes.add_type("image/jpeg", ".jpeg")
mimetypes.add_type("image/png", ".png")
mimetypes.add_type("image/gif", ".gif")
mimetypes.add_type("image/webp", ".webp")

#===============================================================================#
#                    Helpers                                                    #
#===============================================================================#

# ---------- Helpers (fonction additionelles pour les Forums) ----------
# Connexion DB par requête (safe)

@app.before_request
def _pw_connect():
    if peewee_db.is_closed():
        peewee_db.connect(reuse_if_open=True)

@app.teardown_request
def _pw_close(exc):
    if not peewee_db.is_closed():
        peewee_db.close()


def client_ip():
    h = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if h: return h
    return request.remote_addr or "127.0.0.1"


def geo_from_ip(ip: str):
    try:
        if ip in ("127.0.0.1", "::1"):
            return {"city":"Local","country":"—","country_code":""}
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if r.ok:
            j = r.json()
            return {
                    "city": j.get("city") or "",
                    "country": j.get("country_name") or "", 
                    "country_code": (j.get("country_code") or "").upper()
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
        "deleted": bool(c.deleted),
    }

def topic_to_dict(t: Topic):
    comments = (
        Comment
        .select()
        .where(Comment.topic == t.id)
        .order_by(Comment.parent_id.is_null(False), Comment.created_at.asc())
    )
    return {
        "id": t.id,
        "author_name": t.author_name,
        "title": t.title,
        "body": t.body,
        "city": t.city, "country": t.country, "country_code": t.country_code,
        "created_at": (t.created_at or datetime.now(timezone.utc)).isoformat(),
        "comments": [comment_to_dict(c) for c in comments]
    }


def topic_brief_row_to_dict(row):
    t, ccount = row
    return {
        "id": t.id, "author_name": t.author_name, "title": t.title, "body": t.body,
        "city": t.city, "country": t.country, "country_code": t.country_code,
        "created_at": (t.created_at or datetime.now(timezone.utc)).isoformat(),
        "comment_count": int(ccount or 0),
    }

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        uid = session.get("uid")
        if not uid:
            return jsonify({"error": "Login requis."}), 401
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    try:
        return User.get_by_id(uid)
    except Exception:
        return None

def verified_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({"error": "Login requis."}), 401
        if not u.is_verified:
            return jsonify({"error": "Email non vérifié."}), 403
        return fn(*args, **kwargs)
    return wrapper

def _pepper():
    return os.getenv("VERIFICATION_PEPPER", "pepper_change_me")

def hash_code(code: str) -> str:
    return hashlib.sha256((code + _pepper()).encode("utf-8")).hexdigest()

def send_verification_email(to_email: str, code: str):
    # Mode DEV : pas d'email, on log juste
    if os.getenv("SHOW_DEBUG_CODE", "0") in ("1", "true", "yes"):
        logging.info("[DEV] Verification code for %s = %s", to_email, code)
        return

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASSWORD")
    from_addr = os.getenv("SMTP_FROM", user)
    use_tls = os.getenv("SMTP_TLS", "1") in ("1", "true", "yes")

    if not (host and user and pwd):
        raise RuntimeError("SMTP non configuré (HOST/USER/PASS).")

    msg = EmailMessage()
    msg["Subject"] = "ORE MI - Code de validation"
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.set_content(f"Ton code de validation d'abonné ORE MI est : {code}\nIl expire dans 15 minutes.\nNous sommes heureux de vous compter parmi nos chères abonnés.")

    with smtplib.SMTP(host, port, timeout=10) as s:
        if use_tls:
            s.starttls()
        s.login(user, pwd)
        s.send_message(msg)

# ---------- Helpers (fonction additionelles pour les Temoignages) ----------

def _video_public_url(rel_path: str) -> str:
    """Retourne l'URL publique à partir du chemin relatif (servi par static_files)."""
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    return "/" + rel_path

def testimonial_brief_row_to_dict(row):
    """row = (Testimonial, ccount)"""
    t, ccount = row
    return {
        "id": t.id,
        "author_name": t.author_name,
        "title": t.title,
        "video_url": _video_public_url(t.video_path),
        "mime_type": t.mime_type or "video/mp4",
        "city": t.city, "country": t.country, "country_code": t.country_code,
        "created_at": (t.created_at or datetime.now(timezone.utc)).isoformat(),
        "comment_count": int(ccount or 0),
    }

def testimonial_to_dict(t: Testimonial):
    return {
        "id": t.id,
        "author_name": t.author_name,
        "title": t.title,
        "video_url": _video_public_url(t.video_path),
        "mime_type": t.mime_type or "video/mp4",
        "city": t.city, "country": t.country, "country_code": t.country_code,
        "created_at": (t.created_at or datetime.now(timezone.utc)).isoformat(),
    }

def tcomment_to_dict(c: TestimonialComment):
    return {
        "id": c.id,
        "testimonial_id": c.testimonial_id,
        # "parent_id": c.parent_id,
        "author_name": c.author_name,
        "body": "[commentaire supprimé]" if c.deleted else c.body,
        "city": c.city, "country": c.country, "country_code": c.country_code,
        "created_at": (c.created_at or datetime.now(timezone.utc)).isoformat(),
        "updated_at": (c.updated_at.isoformat() if c.updated_at else None),
        "deleted": c.deleted,
    }

def reply_to_dict(r):
    return {
        "id": r.id,
        "comment_id": r.comment_id,
        "author_name": r.author_name,
        "body": r.body,
        "city": r.city,
        "country": r.country,
        "country_code": r.country_code,
        "created_at": (r.created_at or datetime.now(timezone.utc)).isoformat(),
        "updated_at": (r.updated_at.isoformat() if r.updated_at else None),
        "deleted": bool(r.deleted),
    }

def event_to_dict(e):
    """
    Convertit un Event (SQLAlchemy ou Peewee) en dict JSON.
    """
    created_at = getattr(e, "created_at", None) or datetime.now(timezone.utc)
    updated_at = getattr(e, "updated_at", None)

    return {
        "id": getattr(e, "id", None),
        "author_name": getattr(e, "author_name", None),
        "title": getattr(e, "title", None),
        "body": getattr(e, "body", None),

        "media_path": getattr(e, "media_path", None),
        "media_type": getattr(e, "media_type", None),

        "city": getattr(e, "city", None),
        "country": getattr(e, "country", None),
        "country_code": getattr(e, "country_code", None),

        "like_count": int(getattr(e, "like_count", 0) or 0),

        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,

        "deleted": bool(getattr(e, "deleted", False)),
    }

def topic_to_dict(t: Topic) -> dict:
    return {
        "id": t.id,
        "user_id": t.user_id,  # ownership
        "author_name": t.author_name,
        "title": t.title,
        "body": t.body,
        "city": t.city,
        "country": t.country,
        "country_code": t.country_code,
        "created_at": t.created_at.isoformat().replace("+00:00", "Z") if t.created_at else None,
    }

def comment_to_dict(c: Comment) -> dict:
    # Si soft-delete, on masque le contenu, mais on garde la structure du thread
    is_deleted = bool(getattr(c, "deleted", False))

    return {
        "id": c.id,
        "topic_id": c.topic_id,
        "parent_id": c.parent_id,
        "user_id": c.user_id,  # ownership

        "author_name": c.author_name,
        "body": "" if is_deleted else c.body,

        "city": c.city,
        "country": c.country,
        "country_code": c.country_code,

        "created_at": c.created_at.isoformat().replace("+00:00", "Z") if c.created_at else None,
        "updated_at": c.updated_at.isoformat().replace("+00:00", "Z") if getattr(c, "updated_at", None) else None,

        "deleted": is_deleted,
    }


def get_or_404(model, **where):
    try:
        return model.get(**where)
    except DoesNotExist:
        abort(404)

#=========================== Evenements èa venir (avec Images / Videos) ==========================================

def _save_event_media(file_storage):
    name = secure_filename(file_storage.filename or "")
    ext = (os.path.splitext(name)[1] or "").lower()

    if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
        sub = "images"
        mtype = "image"
    elif ext in {".mp4", ".webm", ".ogg"}:
        sub = "videos"
        mtype = "video"
    else:
        raise ValueError("Type de fichier non autorisé")

    # Chemin disque (OK d'utiliser os.path.join ici)
    disk_dir = os.path.join(APP_DIR, "uploads", "events", sub)
    os.makedirs(disk_dir, exist_ok=True)
    disk_path = os.path.join(disk_dir, name)
    file_storage.save(disk_path)

    # >>> Chemin **URL** (jamais os.path.join), avec "/" en tête
    url_path = "/uploads/events/{}/{}".format(sub, name)  # ex: /uploads/events/images/photo.jpg
    url_path = url_path.replace("\\", "/")  # au cas où
    return url_path, mtype  # mtype: "image" ou "video"

#=============================================================#
#         Routes Statiques                                    #
#=============================================================#

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/pourquoi")
def pourquoi():
    return render_template("pourquoi.html")


@app.route("/vos_impressions")
def vos_impressions():
    return render_template("vos_impressions.html")


@app.route("/procedures_administratives")
def procedures_administratives():
    return render_template("procedures_administratives.html")


@app.route("/documents_administratifs")
def documents_administratifs():
    return render_template("documents_administratifs.html")


@app.route("/associations_etudiantes")
def associations_etudiantes():
    return render_template("associations_etudiantes.html")


@app.route("/benevolat")
def benevolat():
    return render_template("benevolat.html")


@app.route("/bibliotheques")
def bibliotheques():
    return render_template("bibliotheques.html")


@app.route("/centres_communautaires")
def centres_communautaires():
    return render_template("centres_communautaires.html")


@app.route("/chatter_en_ligne")
def chatter_en_ligne():
    return render_template("chatter_en_ligne.html")


@app.route("/colocation_vs_appartement")
def colocation_vs_appartement():
    return render_template("colocation_vs_appartement.html")


@app.route("/culture_regionale")
def culture_regionale():
    return render_template("culture_regionale.html")


@app.route("/etudier_a_l_universite_uqac")
def etudier_a_l_universite_uqac():
    return render_template("etudier_a_l_universite_uqac.html")


@app.route("/etudier_a_l_universite")
def etudier_a_l_universite():
    return render_template("etudier_a_l_universite.html")


@app.route("/etudier_a_la_formation_continue")
def etudier_a_la_formation_continue():
    return render_template("etudier_a_la_formation_continue.html")


@app.route("/etudier_a_la_formation_professionnelle")
def etudier_a_la_formation_professionnelle():
    return render_template("etudier_a_la_formation_professionnelle.html")


@app.route("/etudier_au_cegep")
def etudier_au_cegep():
    return render_template("etudier_au_cegep.html")


@app.route("/etudier_au_quebec")
def etudier_au_quebec():
    return render_template("etudier_au_quebec.html")


@app.route("/finances")
def finances():
    return render_template("finances.html")


@app.route("/gestion_des_saisons")
def gestion_des_saisons():
    return render_template("gestion_des_saisons.html")


@app.route("/ici_chez_nous")
def ici_chez_nous():
    return render_template("ici_chez_nous.html")


@app.route("/installations_sportives")
def installations_sportives():
    return render_template("installations_sportives.html")


@app.route("/l_apres_diplome")
def l_apres_diplome():
    return render_template("l_apres_diplome.html")


@app.route("/ou_magasiner")
def ou_magasiner():
    return render_template("ou_magasiner.html")


@app.route("/magasiner_nourritures")
def magasiner_nourritures():
    return render_template("magasiner_nourritures.html")


@app.route("/magasiner_vetements")
def magasiner_vetements():
    return render_template("magasiner_vetements.html")


@app.route("/magasiner_accessoires")
def magasiner_accessoires():
    return render_template("magasiner_accessoires.html")


@app.route("/nos_missions")
def nos_missions():
    return render_template("nos_missions.html")


@app.route("/nos_partenaires")
def nos_partenaires():
    return render_template("nos_partenaires.html")


@app.route("/nous_contacter")
def nous_contacter():
    return render_template("nous_contacter.html")


@app.route("/objets_perdus_retrouves")
def objets_perdus_retrouves():
    return render_template("objets_perdus_retrouves")


@app.route("/participer_aux_evenements")
def participer_aux_evenements():
    return render_template("participer_aux_evenements.html")


@app.route("/qui_sommes_nous")
def qui_sommes_nous():
    return render_template("qui_sommes_nous.html")


@app.route("/services_aide_saguenay")
def services_aide_saguenay():
    return render_template("services_aide_saguenay.html")


@app.route("/services_de_sante")
def services_de_sante():
    return render_template("services_de_sante.html")


@app.route("/travailler_au_quebec")
def travailler_au_quebec():
    return render_template("travailler_au_quebec.html")


@app.route("/trouver_sa_bourse")
def trouver_sa_bourse():
    return render_template("trouver_sa_bourse.html")


@app.route("/trouver_sa_formation")
def trouver_sa_formation():
    return render_template("trouver_sa_formation.html")


@app.route("/trouver_son_emplois")
def trouver_son_emplois():
    return render_template("trouver_son_emplois.html")


@app.route("/trouver_son_etablissement")
def trouver_son_etablissement():
    return render_template("trouver_son_etablissement.html")


@app.route("/trouver_son_logement")
def trouver_son_logement():
    return render_template("trouver_son_logement.html")


@app.route("/trouver_son_visa")
def trouver_son_visa():
    return render_template("trouver_son_visa.html")


@app.route("/vivre_au_quebec")
def vivre_au_quebec():
    return render_template("vivre_au_quebec.html")

#============== FIN des Routes Statiques  ====================#

@app.get("/<path:page>")
def pages(page):
    if page.endswith(".html"):
        return render_template(page)
    abort(404)


@app.get("/communiquer_avec_notre_IA")
def communiquer_avec_notre_IA():
    return render_template("communiquer_avec_notre_IA.html")


@app.get("/evenements_a_venir")
def evenements_a_venir():
    return render_template("evenements_a_venir.html")


@app.get("/uploads/<path:path>", endpoint="serve_uploads")
def serve_uploads(path: str):
    """
    Sert un fichier sous /uploads/** en évitant les traversals (../).
    Exemple d'URL: /uploads/events/images/photo.jpg
                    /uploads/events/videos/clip.mp4
    """
    # Normalise et sécurise le chemin demandé
    safe_path = safe_join(UPLOADS_DIR, path)
    if not safe_path or not os.path.isfile(safe_path):
        # Fichier introuvable (ou tentative d'accès hors de /uploads)
        return abort(404)

    # Flask se base sur 'mimetypes' -> nos add_type() garantissent un Content-Type correct
    # conditional=True => support Range/caching pour les vidéos
    # Le "filename" doit être relatif au dossier passé à send_from_directory
    rel_filename = os.path.relpath(safe_path, UPLOADS_DIR)
    return send_from_directory(UPLOADS_DIR, rel_filename, conditional=True)


_FAVICON_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
@app.get("/favicon.ico")
def favicon():
    png = base64.b64decode(_FAVICON_PNG_B64)
    return app.response_class(png, mimetype="image/png")


@app.get("/health")
def health():
    # return jsonify({"ok": True, "stream": not STREAM_DISABLED}) # pour ACTIVER le STREAM
    return jsonify({"ok": True, "stream": (not STREAM_DISABLED)})

#===================== API Forums / Topics ============================#

@app.get("/topics")
def topics():
    # si tu veux garder /topics -> topics.html
    return render_template("topics.html")

@app.post("/api/auth/register")
def register():
    data = request.get_json(force=True, silent=True) or {}

    first = (data.get("first_name") or "").strip()
    last  = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    city  = (data.get("city") or "").strip()
    pwd   = (data.get("password") or "").strip()

    if not first or not last or not email or not pwd:
        return jsonify({"error": "Champs requis: first_name, last_name, email, password"}), 400

    # create or replace user
    u, created = User.get_or_create(email=email, defaults={
        "first_name": first,
        "last_name": last,
        "city": city or None,
        "password_hash": generate_password_hash(pwd),
        "is_verified": False,
    })
    if not created:
        # si tu repars à neuf, tu peux forcer reset :
        u.first_name = first
        u.last_name = last
        u.email = email
        u.city = city or None
        u.password_hash = generate_password_hash(pwd)
        u.is_verified = False
        u.save()

    # nouveau code 5 digits
    code = f"{random.randint(0, 99999):05d}"
    EmailVerificationCode.create(
        user=u,
        code_hash=hash_code(code),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        used=False
    )

    send_verification_email(u.email, code)

    resp = {"ok": True, "message": "Code envoyé par email."}
    # DEV only: renvoyer le code
    if os.getenv("SHOW_DEBUG_CODE", "0") in ("1", "true", "yes"):
        resp["debug_code"] = code

    return jsonify(resp)

@app.post("/api/auth/verify")
def verify_email():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code  = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"error": "email et code requis."}), 400

    u = get_or_404(User, email=email)

    now = datetime.now(timezone.utc)
    q = (EmailVerificationCode
         .select()
         .where(
            (EmailVerificationCode.user == u.id) &
            (EmailVerificationCode.used == False) &
            (EmailVerificationCode.expires_at > now)
         )
         .order_by(EmailVerificationCode.id.desc())
         .limit(5))

    code_h = hash_code(code)
    ok = None
    for row in q:
        if row.code_hash == code_h:
            ok = row
            break

    if not ok:
        return jsonify({"error": "Code invalide ou expiré."}), 400

    ok.used = True
    ok.save()

    u.is_verified = True
    u.save()

    session["uid"] = u.id
    return jsonify({"ok": True})

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    pwd   = (data.get("password") or "").strip()

    if not email or not pwd:
        return jsonify({"error": "email et password requis."}), 400

    u = get_or_404(User, email=email)
    if not check_password_hash(u.password_hash, pwd):
        return jsonify({"error": "Identifiants invalides."}), 401

    session["uid"] = u.id
    return jsonify({"ok": True, "is_verified": bool(u.is_verified)})

@app.post("/api/auth/logout")
def logout():
    session.pop("uid", None)
    return jsonify({"ok": True})

@app.get("/api/auth/me")
def me():
    u = current_user()
    if not u:
        return jsonify({"user": None})
    return jsonify({"user": {
        "id": u.id,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "email": u.email,
        "city": u.city,
        "is_verified": bool(u.is_verified),
    }})

# GET /api/forum/topics?page=1&page_size=10&q=...&sort=recent|commented
@app.get("/api/forum/topics")
def list_topics():
    print("LIST_TOPICS VERSION FIXED ✅")
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except Exception:
        page = 1

    try:
        page_size = int(request.args.get("page_size", 10))
        if page_size <= 0 or page_size > 50:
            page_size = 10
    except Exception:
        page_size = 10

    qtext = (request.args.get("q") or "").strip()
    sort  = (request.args.get("sort") or "recent").strip().lower()

    where = []
    if qtext:
        where.append(
            (Topic.title.contains(qtext)) |
            (Topic.body.contains(qtext)) |
            (Topic.author_name.contains(qtext))
        )

    # ✅ SAFE COUNT
    q_total = Topic.select()
    if where:
        q_total = q_total.where(*where)
    total = q_total.count()

    total_pages = max(math.ceil(total / page_size), 1)
    if page > total_pages:
        page = total_pages

    base = (
        Topic
        .select(Topic, fn.COUNT(Comment.id).alias("ccount"))
        .join(
            Comment,
            join_type=JOIN.LEFT_OUTER,
            on=((Comment.topic == Topic.id) & (Comment.deleted == False))
        )
        .group_by(Topic.id)
    )

    # ✅ SAFE WHERE
    if where:
        base = base.where(*where)

    if sort == "commented":
        base = base.order_by(fn.COUNT(Comment.id).desc(), Topic.id.desc())
    else:
        base = base.order_by(Topic.id.desc())

    rows = [(t, getattr(t, "ccount", 0)) for t in base.paginate(page, page_size)]

    return jsonify({
        "items": [topic_brief_row_to_dict(r) for r in rows],
        "page": page, "page_size": page_size, "total": total,
        "total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
        "q": qtext, "sort": sort,
    })


@app.get("/api/forum/topics/<int:tid>")
def get_topic(tid: int):
    t = get_or_404(Topic, id=tid)
    return jsonify(topic_to_dict(t))


@app.put("/api/forum/topics/<int:tid>")
@verified_required
def update_topic(tid: int):
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get("title") or "").strip()
    body  = (data.get("body") or "").strip()

    t = get_or_404(Topic, id=tid)
    u = current_user()
    if t.user_id != u.id:
        return jsonify({"error": "Non autorisé."}), 403

    if title: t.title = title
    if body or body == "": t.body = body
    t.save()
    return jsonify({"ok": True})

@app.delete("/api/forum/topics/<int:tid>")
@verified_required
def delete_topic(tid: int):
    t = get_or_404(Topic, id=tid)
    u = current_user()
    if t.user_id != u.id:
        return jsonify({"error": "Non autorisé."}), 403
    # soit hard delete, soit soft delete (à toi de choisir)
    t.delete_instance(recursive=True)
    return jsonify({"ok": True})


@app.post("/api/forum/comments")
@verified_required
def create_comment():
    data = request.get_json(force=True, silent=True) or {}
    topic_id = int(data.get("topic_id") or 0)
    parent_id = data.get("parent_id")
    parent_id = int(parent_id) if parent_id else None

    body = (data.get("body") or "").strip()
    c_city = (data.get("city") or "").strip()
    c_country = (data.get("country") or "").strip()
    c_cc = (data.get("country_code") or "").strip().upper()

    if not topic_id or not body:
        return jsonify({"error": "topic_id et body requis."}), 400

    get_or_404(Topic, id=topic_id)

    u = current_user()
    ip = client_ip()
    g = {"city": c_city, "country": c_country, "country_code": c_cc} if (c_city or c_country or c_cc) else geo_from_ip(ip)

    author = f"{u.first_name} {u.last_name}".strip()

    c = Comment.create(
        topic=topic_id,
        parent=parent_id,
        user=u.id,
        author_name=author,
        body=body,
        city=g["city"],
        country=g["country"],
        country_code=g["country_code"],
        ip_addr=ip,
    )
    return jsonify({"ok": True, "comment": comment_to_dict(c)})


@app.put("/api/forum/comments/<int:cid>")
@verified_required
def update_comment(cid: int):
    data = request.get_json(force=True, silent=True) or {}
    body = (data.get("body") or "").strip()

    c = get_or_404(Comment, id=cid)
    u = current_user()

    if c.user_id != u.id:
        return jsonify({"error": "Non autorisé."}), 403
    if not body:
        return jsonify({"error": "Contenu vide."}), 400

    c.body = body
    c.updated_at = datetime.now(timezone.utc)
    c.save()
    return jsonify({"ok": True, "comment": comment_to_dict(c)})


@app.delete("/api/forum/comments/<int:cid>")
@verified_required
def delete_comment(cid: int):
    c = get_or_404(Comment, id=cid)
    u = current_user()

    if c.user_id != u.id:
        return jsonify({"error": "Non autorisé."}), 403

    c.deleted = True
    c.updated_at = datetime.now(timezone.utc)
    c.save()
    return jsonify({"ok": True})

# ============================================================ #
#                API Témoignages (Peewee) 
# ============================================================ #

# Liste + recherche + tri + pagination
@app.get("/temoignages")
def temoignages():
    return render_template("temoignages.html")


# GET /api/testimonials?page=1&page_size=10&q=...&sort=recent|commented
@app.get("/api/testimonials")
def list_testimonials():
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except Exception:
        page = 1

    try:
        page_size = int(request.args.get("page_size", 10))
        if page_size <= 0 or page_size > 50:
            page_size = 10
    except Exception:
        page_size = 10

    qtext = (request.args.get("q") or "").strip()
    sort  = (request.args.get("sort") or "recent").strip().lower()

    where = []
    if qtext:
        # simple et robuste (LIKE). Si tu veux du vrai "ilike" partout, on le fera après.
        where.append(
            (Testimonial.title.contains(qtext)) |
            (Testimonial.author_name.contains(qtext))
        )

    total = Testimonial.select().where(*where).count()
    total_pages = max(math.ceil(total / page_size), 1)
    if page > total_pages:
        page = total_pages

    base = (
        Testimonial
        .select(Testimonial, fn.COUNT(TestimonialComment.id).alias("ccount"))
        .join(TestimonialComment, join_type=JOIN.LEFT_OUTER, on=(TestimonialComment.testimonial == Testimonial.id))
        .where(*where)
        .group_by(Testimonial.id)
    )

    if sort == "commented":
        base = base.order_by(fn.COUNT(TestimonialComment.id).desc(), Testimonial.id.desc())
    else:
        base = base.order_by(Testimonial.id.desc())

    # On fabrique des tuples (t, ccount) pour réutiliser TON helper tel quel
    rows = [(t, getattr(t, "ccount", 0)) for t in base.paginate(page, page_size)]

    return jsonify({
        "items": [testimonial_brief_row_to_dict(r) for r in rows],
        "page": page, "page_size": page_size, "total": total,
        "total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
        "q": qtext, "sort": sort,
    })


# Récupérer un témoignage
@app.get("/api/testimonials/<int:tid>")
def get_testimonial(tid: int):
    t = get_or_404(Testimonial, id=tid)
    return jsonify(testimonial_to_dict(t))


# Création (upload ≤ 100 Mo)
@app.post("/api/testimonials")
def create_testimonial():
    author = (request.form.get("author_name") or "").strip()
    title  = (request.form.get("title") or "").strip()
    file   = request.files.get("file")

    c_city = (request.form.get("city") or "").strip()
    c_country = (request.form.get("country") or "").strip()
    c_cc = (request.form.get("country_code") or "").strip().upper()

    if not author or not title or not file:
        return jsonify({"error": "Champs requis manquants."}), 400

    # Taille (hard limit)
    content_len = request.content_length or 0
    if content_len > (MAX_VIDEO_MB * 1024 * 1024 + 1024 * 8):
        return jsonify({"error": f"Fichier trop volumineux (> {MAX_VIDEO_MB} Mo)."}), 413

    # Type & extension
    filename = secure_filename(file.filename or "")
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    if ext not in ALLOWED_VIDEO_EXTS:
        return jsonify({"error": f"Extension non autorisée ({ext})."}), 400

    mime = file.mimetype or "video/mp4"
    if not mime.startswith("video/"):
        return jsonify({"error": "Le fichier doit être une vidéo."}), 400

    # Nom unique + enregistrement
    uniq = secrets.token_urlsafe(8)
    safe_name = f"{uniq}.{ext}"
    rel_path = os.path.join("uploads", "videos", safe_name).replace("\\", "/")
    abs_path = os.path.join(APP_DIR, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    file.save(abs_path)

    # Géoloc (depuis client sinon IP)
    ip = client_ip()
    g = {"city": c_city, "country": c_country, "country_code": c_cc} if (c_city or c_country or c_cc) else geo_from_ip(ip)

    t = Testimonial.create(
        author_name=author,
        title=title,
        video_path=rel_path,
        mime_type=mime,
        city=g["city"],
        country=g["country"],
        country_code=g["country_code"],
    )
    return jsonify({"ok": True, "item": testimonial_to_dict(t)})


# Lister les commentaires d’un témoignage
@app.get("/api/testimonials/<int:tid>/comments")
def list_tcomments(tid: int):
    # 404 si témoignage inexistant
    get_or_404(Testimonial, id=tid)

    items = (
        TestimonialComment
        .select()
        .where(TestimonialComment.testimonial == tid)
        .order_by(TestimonialComment.created_at.asc())
    )
    return jsonify({"items": [tcomment_to_dict(c) for c in items]})


# Créer un commentaire (renvoie token)
# POST /api/testimonials/comments — JSON {testimonial_id, author_name, body, (city,country,country_code)}
@app.post("/api/testimonials/comments")
def create_tcomment():
    data = request.get_json(force=True, silent=True) or {}
    tid = int(data.get("testimonial_id") or 0)

    author = (data.get("author_name") or "").strip()
    body   = (data.get("body") or "").strip()

    c_city    = (data.get("city") or "").strip()
    c_country = (data.get("country") or "").strip()
    c_cc      = (data.get("country_code") or "").strip().upper()

    if not tid or not author or not body:
        return jsonify({"error": "Champs requis manquants."}), 400

    get_or_404(Testimonial, id=tid)

    ip = client_ip()
    g = {"city": c_city, "country": c_country, "country_code": c_cc} if (c_city or c_country or c_cc) else geo_from_ip(ip)

    token = secrets.token_urlsafe(16)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    c = TestimonialComment.create(
        testimonial=tid,
        author_name=author,
        body=body,
        city=g["city"],
        country=g["country"],
        country_code=g["country_code"],
        ip_addr=ip,
        edit_token_hash=token_hash,
    )

    return jsonify({"ok": True, "comment": tcomment_to_dict(c), "token": token})


# Lister les réponses d’un commentaire
@app.get("/api/testimonials/comments/<int:cid>/replies")
def list_replies(cid: int):
    items = (
        TestimonialReply
        .select()
        .where((TestimonialReply.comment == cid) & (TestimonialReply.deleted == False))
        .order_by(TestimonialReply.created_at.asc())
    )
    return jsonify({"items": [reply_to_dict(r) for r in items]})


# Créer une réponse (retourne token)
@app.post("/api/testimonials/replies")
def create_reply():
    data = request.get_json(force=True, silent=True) or {}
    cid = int(data.get("comment_id") or 0)
    author = (data.get("author_name") or "").strip()
    body   = (data.get("body") or "").strip()

    if not cid or not author or not body:
        return jsonify({"error": "comment_id, author_name et body requis."}), 400

    # 404 si le commentaire n'existe pas
    get_or_404(TestimonialComment, id=cid)

    token = secrets.token_urlsafe(16)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    r = TestimonialReply.create(
        comment=cid,
        author_name=author,
        body=body,
        city=None,
        country=None,
        country_code=None,
        edit_token_hash=token_hash,
    )
    return jsonify({"ok": True, "reply": reply_to_dict(r), "token": token})


# Modifier une réponse
@app.put("/api/testimonials/replies/<int:rid>")
def update_reply(rid: int):
    data = request.get_json(force=True, silent=True) or {}
    tok  = (data.get("token") or "").strip()
    body = (data.get("body") or "").strip()

    r = get_or_404(TestimonialReply, id=rid)
    if not r.can_edit(tok):
        return jsonify({"error": "Non autorisé."}), 403
    if not body:
        return jsonify({"error": "Le texte est requis."}), 400

    r.body = body
    r.updated_at = datetime.now(timezone.utc)
    r.save()
    return jsonify({"ok": True, "reply": reply_to_dict(r)})


# Supprimer une réponse (soft-delete)
@app.delete("/api/testimonials/replies/<int:rid>")
def delete_reply(rid: int):
    data = request.get_json(force=True, silent=True) or {}
    tok = (data.get("token") or "").strip()

    r = get_or_404(TestimonialReply, id=rid)
    if not r.can_edit(tok):
        return jsonify({"error": "Non autorisé."}), 403

    r.deleted = True
    r.updated_at = datetime.now(timezone.utc)
    r.save()
    return jsonify({"ok": True})


# Modifier un commentaire
@app.put("/api/testimonials/comments/<int:cid>")
def update_tcomment(cid: int):
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    body  = (data.get("body") or "").strip()

    c = get_or_404(TestimonialComment, id=cid)
    if not c.can_edit(token):
        return jsonify({"error": "Non autorisé."}), 403
    if not body:
        return jsonify({"error": "Contenu vide."}), 400

    c.body = body
    c.updated_at = datetime.now(timezone.utc)
    c.save()
    return jsonify({"ok": True, "comment": tcomment_to_dict(c)})


# Supprimer (soft-delete) un commentaire
@app.delete("/api/testimonials/comments/<int:cid>")
def delete_tcomment(cid: int):
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()

    c = get_or_404(TestimonialComment, id=cid)
    if not c.can_edit(token):
        return jsonify({"error": "Non autorisé."}), 403

    c.deleted = True
    c.updated_at = datetime.now(timezone.utc)
    c.save()
    return jsonify({"ok": True})

#==================================================================#
#             API ajouter un evenement (image / video)             #
#==================================================================#

@app.get("/api/events")
def list_events():
    try:
        page = max(1, int(request.args.get("page", "1")))
    except Exception:
        page = 1

    try:
        page_size = int(request.args.get("page_size", "10"))
        page_size = min(50, max(1, page_size))
    except Exception:
        page_size = 10

    sort = (request.args.get("sort") or "recent").lower()

    q = Event.select().where(Event.deleted == False)

    if sort == "recent":
        q = q.order_by(Event.created_at.desc())
    else:
        q = q.order_by(Event.created_at.asc())

    items = q.paginate(page, page_size)
    return jsonify({"items": [event_to_dict(e) for e in items]})


@app.get("/api/events/<int:eid>")
def get_event(eid: int):
    e = get_or_404(Event, id=eid)
    if e.deleted:
        abort(404)
    return jsonify({"event": event_to_dict(e)})


@app.post("/api/events")
def create_event():
    """
    multipart:
      - author_name, title, body
      - media (file) optionnel
    Retourne token d'édition.
    """
    author = (request.form.get("author_name") or "").strip()
    title  = (request.form.get("title") or "").strip()
    body   = (request.form.get("body") or "").strip()

    if not author or not title:
        return jsonify({"error": "author_name et title sont requis."}), 400

    media_rel, media_type = None, None
    f = request.files.get("media")
    try:
        if f and f.filename:
            media_rel, media_type = _save_event_media(f)
    except ValueError as ex:
        return jsonify({"error": str(ex)}), 400

    geo = geo_from_ip(client_ip())
    token = secrets.token_urlsafe(16)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    e = Event.create(
        author_name=author,
        title=title,
        body=body,
        media_path=media_rel,
        media_type=media_type,
        city=geo["city"],
        country=geo["country"],
        country_code=geo["country_code"],
        edit_token_hash=token_hash,
    )
    return jsonify({"ok": True, "event": event_to_dict(e), "token": token})


# Mise à jour sans changer le média (JSON)
@app.put("/api/events/<int:eid>")
def update_event_json(eid: int):
    e = get_or_404(Event, id=eid)
    data = request.get_json(force=True, silent=True) or {}

    token = (data.get("token") or "").strip()
    if not e.can_edit(token):
        return jsonify({"error": "Non autorisé."}), 403

    title = (data.get("title") or "").strip()
    body  = (data.get("body") or "").strip()

    if title:
        e.title = title
    # autoriser body vide
    if body or body == "":
        e.body = body

    e.updated_at = datetime.now(timezone.utc)
    e.save()

    return jsonify({"ok": True, "event": event_to_dict(e)})


# Mise à jour AVEC changement de média (multipart)
# (oui, tu as /api/events/<eid> en POST pour ça — on garde pareil)
@app.post("/api/events/<int:eid>")
def update_event_with_media(eid: int):
    e = get_or_404(Event, id=eid)

    token = (request.form.get("token") or "").strip()
    if not e.can_edit(token):
        return jsonify({"error": "Non autorisé."}), 403

    title = (request.form.get("title") or "").strip()
    body  = (request.form.get("body") or "").strip()

    if title:
        e.title = title
    if body or body == "":
        e.body = body

    f = request.files.get("media")
    if f and f.filename:
        try:
            media_rel, media_type = _save_event_media(f)
            e.media_path = media_rel
            e.media_type = media_type
        except ValueError as ex:
            return jsonify({"error": str(ex)}), 400

    e.updated_at = datetime.now(timezone.utc)
    e.save()
    return jsonify({"ok": True, "event": event_to_dict(e)})


@app.delete("/api/events/<int:eid>")
def delete_event(eid: int):
    e = get_or_404(Event, id=eid)
    data  = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()

    if not e.can_edit(token):
        return jsonify({"error": "Non autorisé."}), 403

    e.deleted = True
    e.updated_at = datetime.now(timezone.utc)
    e.save()

    return jsonify({"ok": True})


@app.post("/api/events/<int:eid>/like")
def like_event(eid: int):
    e = get_or_404(Event, id=eid)
    if e.deleted:
        abort(404)

    e.like_count = int(e.like_count or 0) + 1
    e.save()

    return jsonify({"ok": True, "like_count": e.like_count})

#==================================================================#
#                   Chat avec l'IA                                 #
#==================================================================#

# ---------- IA (import robuste) ----------

import importlib.util, inspect, traceback

try:
    from entrainement_chat import generate_reply as _generate_reply
except Exception as e:
    print("❌ Import entrainement_chat.generate_reply FAILED:", repr(e))
    traceback.print_exc()
    _generate_reply = None

_stream_reply = None
try:
    from entrainement_chat import stream_reply as _stream_reply
except Exception as e:
    try:
        from entrainement_chat import generate_reply_stream as _stream_reply
    except Exception as e2:
        print("❌ Import entrainement_chat.stream_reply FAILED:", repr(e))
        print("❌ Import entrainement_chat.generate_reply_stream FAILED:", repr(e2))
        traceback.print_exc()
        _stream_reply = None

def _fallback_generate(prompt: str, history=None) -> str:
    return "Je n'ai pas accès à ton moteur IA local. (fallback) — Message reçu: " + prompt[:200]

def _fallback_stream(prompt: str, history=None):
    txt = _fallback_generate(prompt, history)
    for ch in txt:
        yield ch
        time.sleep(0.005)

# Petit endpoint de diagnostic
@app.get("/diag/ia")
def diag_ia():
    return jsonify({"generate": bool(_generate_reply), "stream": bool(_stream_reply)})

# ---------- IA: routes unifiées + compat ----------
# Normaliser les appels pour accepter 1 ou 2 paramètres :

def _call_generate(prompt, history):
    """Appelle generate_reply avec (message, history) ou (message) selon la signature."""
    fn = _generate_reply or _fallback_generate
    try:
        if len(inspect.signature(fn).parameters) >= 2:
            return fn(prompt, history)
        return fn(prompt)
    except TypeError:
        # si l’IA ne supporte qu’un paramètre
        return fn(prompt)

def _iter_stream(prompt, history):
    """Itère un flux de tokens en tolérant 1 ou 2 paramètres et le cas string."""
    fn = _stream_reply
    if fn is None:
        # pas de stream fourni → dégrader en non-stream char-par-char
        txt = _call_generate(prompt, history)
        for ch in txt:
            yield ch
        return
    try:
        if len(inspect.signature(fn).parameters) >= 2:
            res = fn(prompt, history)
        else:
            res = fn(prompt)
    except TypeError:
        res = fn(prompt)

    # Si la fonction retourne une string au lieu d’un itérateur
    if isinstance(res, str):
        for ch in res:
            yield ch
    else:
        for token in res:
            yield token

def _messages_to_prompt(messages):
    lines = []
    for m in messages or []:
        role = (m.get("role") or "").strip().lower()
        content = (m.get("content") or "").strip()
        if not content:
            continue
        if role == "system":      lines.append(f"[SYSTEM] {content}")
        elif role == "assistant": lines.append(f"[AI] {content}")
        else:                     lines.append(f"[USER] {content}")
    return "\n".join(lines)

@app.route("/api/chat", methods=["POST", "GET"])
def api_chat_non_stream():
    """Non-stream. Accepte {message,history} ET {messages:[...]} (compat)."""
    if request.method == "GET":
        prompt = (request.args.get("message") or "").strip()
        history = []
    else:
        data = request.get_json(force=True, silent=True) or {}
        if data.get("messages") is not None:  # compat ancien client
            prompt = _messages_to_prompt(data.get("messages"))
            history = []
        else:
            prompt  = (data.get("message") or "").strip()
            history = data.get("history") or []

    if not prompt:
        return jsonify({"error": "message manquant"}), 400

    text = _call_generate(prompt, history)
    return jsonify({"text": text, "reply": text})

@app.route("/api/chat/stream", methods=["POST", "GET"])
def api_chat_stream():
    """Stream SSE JSON: data: {"text": "..."} puis data: {"done": true}."""
    
    # (Facultatif mais propre) Protéger les routes stream pour éviter qu’on les utilise si OFF :
    if STREAM_DISABLED:
        return jsonify({"error":"stream disabled"}), 503
    
    if request.method == "GET":
        prompt = (request.args.get("message") or "").strip()
        history = []
    else:
        data = request.get_json(force=True, silent=True) or {}
        prompt  = (data.get("message") or "").strip()
        history = data.get("history") or []

    if not prompt:
        return jsonify({"error": "message manquant"}), 400

    def event_stream():
        try:
            for token in _iter_stream(prompt, history):
                yield f'data: {json.dumps({"text": token}, ensure_ascii=False)}\n\n'
            yield 'data: {"done": true}\n\n'
        except GeneratorExit:
            pass
        except Exception as e:
            yield f'data: {json.dumps({"error": str(e)})}\n\n'


    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)

@app.post("/api/chat_stream")
def api_chat_stream_compat():
    """Compat ancien front: endpoint /api/chat_stream, flux TEXTE (pas JSON) + event: done."""
    data = request.get_json(force=True, silent=True) or {}
    
    # (Facultatif mais propre) Protéger les routes stream pour éviter qu’on les utilise si OFF :
    if STREAM_DISABLED:
        return jsonify({"error":"stream disabled"}), 503
    
    if data.get("messages") is not None:
        prompt = _messages_to_prompt(data.get("messages"))
        history = []
    else:
        prompt  = (data.get("message") or "").strip()
        history = data.get("history") or []

    if not prompt:
        return jsonify({"error": "message manquant"}), 400

    def event_stream():
        try:
            for token in _iter_stream(prompt, history):
                # Texte brut attendu par l'ancien front
                yield f"data: {token}\n\n"
            # Signal de fin attendu: event: done
            yield "event: done\ndata: [DONE]\n\n"
        except GeneratorExit:
            pass
        except Exception as e:
            yield f"event: error\ndata: {str(e)}\n\n"

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)


#====================== Run ==================================#

if __name__ == "__main__":
    port = int(os.getenv("PORT", "4000"))
    app.run(host="0.0.0.0", port=port, debug=True)
