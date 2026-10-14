"""
Modelo ORM para almacenar el historial de análisis de phishing.

Minimización de datos: no se guarda el texto de los emails ni la URL
completa, ni la explicación o los indicadores (pueden citar fragmentos del
mensaje). Sólo se conserva lo necesario para estadísticas y auditoría:
tipo, veredicto, score, modo de análisis, fecha, el dominio del remitente o
de la URL, y una huella SHA-256 del contenido para reconocer duplicados sin
poder reconstruirlo.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.database import Base


class Analysis(Base):
    """Registro minimizado de un análisis realizado (URL o email)."""

    __tablename__ = "analyses"

    # Identificador único en formato UUID (string para compatibilidad SQLite)
    id = Column(String(36), primary_key=True, index=True)

    # Tipo de análisis: "url" o "email"
    type = Column(String(16), nullable=False, index=True)

    # Score numérico 0-100
    score = Column(Integer, nullable=False)

    # Veredicto: PHISHING | SOSPECHOSO | LEGÍTIMO | NO CONCLUYENTE
    verdict = Column(String(32), nullable=False, index=True)

    # "ai" o "fallback" (heurística sin IA). NULL en registros migrados.
    analysis_mode = Column(String(16), nullable=True)

    # Hostname de la URL o dominio del remitente del email (si se conoce)
    target_domain = Column(String(255), nullable=True)

    # SHA-256 (hex) de la URL normalizada o del texto del email saneado
    input_hash = Column(String(64), nullable=True)

    # Marca temporal de creación
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        """Convierte el registro en un diccionario serializable para la API."""
        return {
            "id": self.id,
            "type": self.type,
            "score": self.score,
            "verdict": self.verdict,
            "analysis_mode": self.analysis_mode,
            "domain": self.target_domain,
            "fingerprint": self.input_hash[:16] if self.input_hash else None,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
