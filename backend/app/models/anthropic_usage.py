"""
Registro de cada llamada a la API de Anthropic Claude.

Se usa para aplicar límites de peticiones por hora y por día y proteger
los créditos de la cuenta. Cada fila representa un intento de análisis con IA.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer

from app.database import Base


class AnthropicUsageLog(Base):
    """Log de consumo de la API de Anthropic."""

    __tablename__ = "anthropic_usage_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    called_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
