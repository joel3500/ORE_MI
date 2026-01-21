# ore_mi_bd.py
import os
import hashlib
from datetime import datetime, timezone, timedelta 

from peewee import (
    Model, AutoField, CharField, TextField, DateTimeField,
    BooleanField, IntegerField, ForeignKeyField, DatabaseProxy
)
from playhouse.db_url import connect as connect_db_url
from peewee import SqliteDatabase


APP_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_PATH = os.path.join(APP_DIR, "ore_mi.db")

# DatabaseProxy = permet d'initialiser la DB PLUS TARD (après lecture .env, après boot, etc.)
db = DatabaseProxy()

def _now_utc():
    return datetime.now(timezone.utc)


def _normalize_db_url(url: str) -> str:
    """
    Certains providers donnent postgres://... alors que la lib attend postgresql://...
    """
    url = (url or "").strip()
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def _sqlite_fallback() -> SqliteDatabase:
    """
    SQLite fallback (FK activées + WAL pour mieux encaisser plusieurs requêtes).
    """
    return SqliteDatabase(
        SQLITE_PATH,
        pragmas={
            "foreign_keys": 1,
            "journal_mode": "wal",
            "cache_size": -1024 * 64,  # ~64MB
        },
    )


class BaseModel(Model):
    class Meta:
        database = db

# ==========================
#        MODELES
# ==========================

class User(BaseModel):
    id = AutoField()
    first_name = CharField(max_length=80)
    last_name  = CharField(max_length=80)
    email      = CharField(max_length=180, unique=True, index=True)
    city       = CharField(max_length=120, null=True)

    password_hash = CharField(max_length=255)
    is_verified   = BooleanField(default=False)

    created_at = DateTimeField(default=_now_utc)


class EmailVerificationCode(BaseModel):
    id = AutoField()
    user = ForeignKeyField(User, backref="verification_codes", on_delete="CASCADE", index=True)

    code_hash  = CharField(max_length=128)   # sha256(code + pepper)
    expires_at = DateTimeField()
    used       = BooleanField(default=False)

    created_at = DateTimeField(default=_now_utc)


class Topic(BaseModel):
    id = AutoField()
    user = ForeignKeyField(User, backref="topics", on_delete="CASCADE", index=True)

    author_name = CharField(max_length=160)
    title = CharField(max_length=240)
    body = TextField()
    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)
    created_at = DateTimeField(default=_now_utc)


class Comment(BaseModel):
    id = AutoField()
    topic = ForeignKeyField(Topic, backref="comments", on_delete="CASCADE", index=True)
    parent = ForeignKeyField("self", null=True, backref="children", on_delete="CASCADE", index=True)

    user = ForeignKeyField(User, backref="comments", on_delete="CASCADE", index=True)

    author_name = CharField(max_length=160)
    body = TextField()
    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)
    ip_addr = CharField(max_length=64, null=True)

    created_at = DateTimeField(default=_now_utc)
    updated_at = DateTimeField(null=True)
    deleted = BooleanField(default=False)


class Testimonial(BaseModel):
    id = AutoField()
    author_name = CharField(max_length=160)
    title = CharField(max_length=240)
    video_path = CharField(max_length=512)
    mime_type = CharField(max_length=64, null=True)

    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)

    created_at = DateTimeField(default=_now_utc)


class TestimonialComment(BaseModel):
    id = AutoField()
    testimonial = ForeignKeyField(Testimonial, backref="comments", on_delete="CASCADE", index=True)

    author_name = CharField(max_length=160)
    body = TextField()
    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)
    ip_addr = CharField(max_length=64, null=True)

    created_at = DateTimeField(default=_now_utc)
    updated_at = DateTimeField(null=True)
    deleted = BooleanField(default=False)


class TestimonialReply(BaseModel):
    id = AutoField()
    comment = ForeignKeyField(TestimonialComment, backref="replies", on_delete="CASCADE", index=True)

    author_name = CharField(max_length=160)
    body = TextField()
    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)

    created_at = DateTimeField(default=_now_utc)
    updated_at = DateTimeField(null=True)
    deleted = BooleanField(default=False)
   

class Event(BaseModel):
    id = AutoField()
    author_name = CharField(max_length=160)
    title = CharField(max_length=240)
    body = TextField()

    media_path = CharField(max_length=400, null=True)
    media_type = CharField(max_length=16, null=True)  # image|video

    city = CharField(max_length=120, null=True)
    country = CharField(max_length=120, null=True)
    country_code = CharField(max_length=8, null=True)

    like_count = IntegerField(default=0)

    created_at = DateTimeField(default=_now_utc)
    updated_at = DateTimeField(null=True)
    deleted = BooleanField(default=False)

   
def init_db():
    """
    À appeler AU DÉMARRAGE de l'app :
    - tente PostgreSQL via DATABASE_URL/POSTGRES_URL
    - sinon fallback SQLite
    - crée les tables si besoin
    """
    url = _normalize_db_url(os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL") or "")
    chosen = None

    if url:
        try:
            chosen = connect_db_url(url, autoconnect=False)
            chosen.connect(reuse_if_open=True)
            chosen.close()
            print("[DB] PostgreSQL OK")
        except Exception as e:
            print(f"[DB] PostgreSQL KO -> fallback SQLite. Raison: {e}")
            chosen = None

    if chosen is None:
        chosen = _sqlite_fallback()
        print("[DB] SQLite OK (fallback)")

    # branche le proxy
    db.initialize(chosen)

    # crée les tables (safe=True = ne recrée pas si déjà existantes)
    chosen.connect(reuse_if_open=True)
    chosen.create_tables(
        [User, EmailVerificationCode, Topic, Comment, Testimonial, TestimonialComment, TestimonialReply, Event],
        safe=True
    )
    chosen.close()

    return chosen
