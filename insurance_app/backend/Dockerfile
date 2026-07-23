FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN addgroup --gid 1001 appgroup && adduser --uid 1001 --gid 1001 --system appuser \
    && mkdir -p /app/uploads \
    && chown -R appuser:appgroup /app
USER 1001
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
