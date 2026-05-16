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

WORKDIR /app

# Instalamos primero las dependencias para aprovechar la caché de Docker
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copiamos el código de la aplicación
COPY app ./app

EXPOSE 8000

# Lanzamos Uvicorn como servidor ASGI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
