# Imagen base ligera de Python 3.11
FROM python:3.11-slim

# Evita la generación de .pyc y fuerza salida sin buffer en logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Dependencias del sistema necesarias para python-whois y compilaciones puntuales
RUN apt-get update \
    && apt-get install -y --no-install-recommends whois ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Creamos un usuario no privilegiado para correr la aplicación.
# UID/GID 10001 está fuera del rango típico del sistema, evitando colisiones.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Instalamos primero las dependencias para aprovechar la caché de Docker
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copiamos el código de la aplicación asignando la propiedad al usuario no-root
COPY --chown=appuser:appuser app ./app

# Directorio del volumen de datos (montado por docker-compose). Lo creamos
# con la propiedad correcta para que SQLite pueda escribir como appuser.
RUN mkdir -p /data && chown -R appuser:appuser /data /app

# A partir de aquí el contenedor corre SIN privilegios de root
USER appuser

EXPOSE 8000

# Lanzamos Uvicorn como servidor ASGI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
