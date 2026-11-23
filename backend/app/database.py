"""
Configuración de la base de datos usando SQLAlchemy.

Define el motor, la sesión y la base declarativa que utilizarán los modelos
ORM del proyecto. Por defecto se usa SQLite; DATABASE_URL permite apuntar a
otro fichero SQLite o a PostgreSQL (postgres://… o postgresql://…, se usa el
driver psycopg 3).

En Render (y otros PaaS con filesystem efímero):
  - El directorio de la app puede ser de solo lectura o borrarse en cada deploy.
  - Si no defines DATABASE_URL, se usa /tmp/phishguard.db, que se borra en
    cada arranque: historial y cuotas de IA no persisten.
  - Para persistir sin disco de pago, define DATABASE_URL con un PostgreSQL
    gestionado (Neon, Supabase…).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)


def _sqlite_filesystem_path(database_url: str) -> str | None:
    """
    Extrae la ruta del fichero .db de una URL SQLite.

    Ejemplos:
      sqlite:////tmp/phishguard.db  -> /tmp/phishguard.db
      sqlite:///./phishguard.db     -> ./phishguard.db
    """
    if not database_url.startswith("sqlite"):
        return None
    if database_url.endswith(":memory:") or database_url.rstrip("/").endswith(":memory:"):
        return None

    if database_url.startswith("sqlite:////"):
        # Ruta absoluta: sqlite:////tmp/db.db -> /tmp/db.db
        return "/" + database_url[len("sqlite:////") :]
    if database_url.startswith("sqlite:///"):
        return database_url[len("sqlite:///") :]
    if database_url.startswith("sqlite://"):
        return database_url[len("sqlite://") :]

    return None


def _normalize_database_url(url: str) -> str:
    """
    Fuerza el driver psycopg 3 en URLs de PostgreSQL.

    Los proveedores entregan postgres://… o postgresql://…; SQLAlchemy no
    acepta el primero y con el segundo buscaría psycopg2, que no se instala.
    """
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def _running_on_render() -> bool:
    return bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))


def _resolve_database_url() -> str:
    """
    Determina la URL de la base de datos según el entorno.

    Prioridad:
      1. Variable DATABASE_URL explícita (Render, Docker, producción).
      2. En Render sin DATABASE_URL: /tmp (escribible en el contenedor).
      3. Local: ./phishguard.db en el directorio de trabajo.
    """
    explicit = os.getenv("DATABASE_URL", "").strip()
    if explicit:
        return _normalize_database_url(explicit)

    if _running_on_render():
        # Render inyecta RENDER=true en todos los servicios web.
        return "sqlite:////tmp/phishguard.db"

    return "sqlite:///./phishguard.db"


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """Crea el directorio padre del fichero SQLite si no existe."""
    db_path = _sqlite_filesystem_path(database_url)
    if not db_path:
        return
    parent = Path(db_path).expanduser().resolve().parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
        logger.info("Directorio de SQLite creado: %s", parent)


DATABASE_URL = _resolve_database_url()
IS_SQLITE = DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    # check_same_thread=False permite que varias hebras de FastAPI usen la
    # misma conexión SQLite.
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # Los PostgreSQL gestionados cierran conexiones inactivas: pre_ping las
    # descarta antes de usarlas en lugar de devolver un 500.
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)

# Fábrica de sesiones que usaremos como dependencia en los routers
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Clase base de la que heredarán todos los modelos
Base = declarative_base()


def get_db():
    """Dependencia de FastAPI que devuelve una sesión y la cierra al final."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _parse_legacy_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.utcnow()


def _legacy_email_domain(text_value: str) -> str | None:
    match = re.search(r"^from:.*?[\w\.\-+]+@([\w\.-]+)", text_value or "", re.IGNORECASE | re.MULTILINE)
    return match.group(1).lower() if match else None


def _migrate_legacy_analyses() -> None:
    """
    Convierte la tabla `analyses` del esquema anterior (que guardaba el texto
    completo de los emails, la URL, la explicación y los indicadores) al
    esquema minimizado. Los datos personales se descartan y el fichero SQLite
    se compacta con VACUUM para que no queden en páginas libres.
    """
    insp = inspect(engine)
    if "analyses" not in insp.get_table_names():
        return
    columns = {col["name"] for col in insp.get_columns("analyses")}
    if "input_data" not in columns:
        return

    from app.models.analysis import Analysis

    logger.warning("Migrando 'analyses' al esquema minimizado: se descarta el contenido analizado.")
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT id, type, url, input_data, score, verdict, timestamp FROM analyses")
        ).mappings().all()
        conn.execute(text("DROP TABLE analyses"))
        Analysis.__table__.create(bind=conn)

        minimized = []
        for row in rows:
            source = row["url"] or row["input_data"] or ""
            if row["type"] == "url":
                domain = (urlparse(source).hostname or None) if "://" in source else None
            else:
                domain = _legacy_email_domain(row["input_data"])
            minimized.append({
                "id": row["id"],
                "type": row["type"],
                "score": row["score"],
                "verdict": row["verdict"],
                "analysis_mode": None,
                "target_domain": domain,
                "input_hash": hashlib.sha256(source.encode("utf-8")).hexdigest() if source else None,
                "timestamp": _parse_legacy_timestamp(row["timestamp"]),
            })
        if minimized:
            conn.execute(Analysis.__table__.insert(), minimized)

    if IS_SQLITE:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.exec_driver_sql("VACUUM")
    logger.warning("Migración completada: %d registros minimizados.", len(rows))


def init_db() -> None:
    """Crea todas las tablas declaradas en los modelos si no existen."""
    _ensure_sqlite_parent_dir(DATABASE_URL)

    # Importamos los modelos para que queden registrados en Base.metadata
    from app.models import analysis, anthropic_usage  # noqa: F401

    try:
        _migrate_legacy_analyses()
        Base.metadata.create_all(bind=engine)
        logger.info(
            "Base de datos inicializada (%s)",
            _sqlite_filesystem_path(DATABASE_URL) or engine.url.render_as_string(hide_password=True).split("?")[0],
        )
        if IS_SQLITE and _running_on_render():
            logger.warning(
                "SQLite en el disco efímero de Render: historial y cuotas de IA se pierden "
                "en cada arranque. Define DATABASE_URL con un PostgreSQL gestionado."
            )
    except Exception as exc:
        logger.exception("Error al inicializar la base de datos: %s", exc)
        raise
