FROM python:3.12-slim

WORKDIR /app

# Dependances systeme
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dependances Python
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Code source
COPY . .

# Creer le dossier data
RUN mkdir -p /app/data

# Port API
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Commande par defaut : API
CMD ["uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8080"]
