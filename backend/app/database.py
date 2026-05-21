"""
Configuración de la base de datos SQLite usando SQLAlchemy.

Define el motor, la sesión y la base declarativa que utilizarán los modelos
ORM del proyecto. La ruta del fichero SQLite se puede sobrescribir mediante
la variable de entorno DATABASE_URL.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# URL de conexión: por defecto se crea un fichero local en backend/phishguard.db
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")

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
    # Importamos los modelos para que queden registrados en Base.metadata
    from app.models import analysis, anthropic_usage  # noqa: F401

    Base.metadata.create_all(bind=engine)
