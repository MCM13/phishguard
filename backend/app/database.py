"""
Configuración de la base de datos SQLite usando SQLAlchemy.

Define el motor, la sesión y la base declarativa que utilizarán los modelos
ORM del proyecto. La ruta del fichero SQLite se puede sobrescribir mediante
la variable de entorno DATABASE_URL.

En Render (y otros PaaS con filesystem efímero):
  - El directorio de la app puede ser de solo lectura o borrarse en cada deploy.
  - Si no defines DATABASE_URL, se usa automáticamente /tmp/phishguard.db
    (siempre escribible). Los datos se pierden al redeploy salvo que montes
    un Persistent Disk y apuntes DATABASE_URL a esa ruta.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy import create_engine
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
        return explicit

    if os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"):
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

# El argumento check_same_thread sólo es necesario en SQLite para permitir
# que varias hebras de FastAPI puedan usar la misma conexión.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

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


def init_db() -> None:
    """Crea todas las tablas declaradas en los modelos si no existen."""
    _ensure_sqlite_parent_dir(DATABASE_URL)

    # Importamos los modelos para que queden registrados en Base.metadata
    from app.models import analysis, anthropic_usage  # noqa: F401

    try:
        Base.metadata.create_all(bind=engine)
        logger.info(
            "Base de datos inicializada (%s)",
            _sqlite_filesystem_path(DATABASE_URL) or DATABASE_URL.split("?")[0],
        )
    except Exception as exc:
        logger.exception("Error al inicializar la base de datos: %s", exc)
        raise
