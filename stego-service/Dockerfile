# syntax=docker/dockerfile:1
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# Usuario sin privilegios; /data es el volumen de STEGO (SQLite + cuarentena).
# La clave pública llega por volumen :ro en /run/keys; nunca se copia en la imagen.
RUN useradd -r -u 10001 -s /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown app:app /data
USER app
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
