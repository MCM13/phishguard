"""
Modelo ORM para almacenar el historial de análisis de phishing.

Cada registro representa un análisis individual de una URL o un email,
incluyendo el score asignado por la IA, el veredicto final y los
indicadores que se detectaron.
"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON

from app.database import Base


class Analysis(Base):
    """Registro de un análisis realizado (URL o email)."""

    __tablename__ = "analyses"

    # Identificador único en formato UUID (string para compatibilidad SQLite)
    id = Column(String(36), primary_key=True, index=True)

    # Tipo de análisis: "url" o "email"
    type = Column(String(16), nullable=False, index=True)

    # Entrada original que se analizó (URL completa o texto del email)
    # Se trunca a un máximo razonable para evitar entradas gigantescas
    input_data = Column(Text, nullable=False)

    # URL detectada/analizada (sólo para análisis de tipo URL)
    url = Column(Text, nullable=True)

    # Score numérico 0-100 devuelto por la IA
    score = Column(Integer, nullable=False)

    # Veredicto: PHISHING | SOSPECHOSO | LEGÍTIMO
    verdict = Column(String(32), nullable=False, index=True)

    # Indicadores devueltos por la IA (lista de dicts serializada a JSON)
    indicators = Column(JSON, nullable=False, default=list)

    # Explicación generada por Claude
    ai_explanation = Column(Text, nullable=False, default="")

    # Número de motores de VirusTotal que marcaron la URL como maliciosa
    virustotal_detections = Column(Integer, nullable=True, default=0)

    # Marca temporal de creación
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        """Convierte el registro en un diccionario serializable para la API."""
        return {
            "id": self.id,
            "type": self.type,
            "input": self.input_data,
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "indicators": self.indicators or [],
            "ai_explanation": self.ai_explanation,
            "virustotal_detections": self.virustotal_detections,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
