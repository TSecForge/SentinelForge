FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/sentinelforge

# 1) the sentinelforge library (with its built-in rule packs) + server dependencies
COPY pyproject.toml README.md LICENSE NOTICE CHANGELOG.md ./
COPY src src
COPY detection-rules detection-rules
COPY backend/requirements.txt backend/requirements.txt
RUN cd backend && pip install --no-cache-dir -r requirements.txt

# 2) server code and runtime data (custom rules, demo inventories, collector, plugins)
COPY backend/app backend/app
COPY custom-rules custom-rules
COPY sample-data sample-data
COPY collectors collectors
COPY plugins plugins

RUN useradd --system --uid 10001 sentinelforge && chown -R sentinelforge /srv/sentinelforge
USER sentinelforge
WORKDIR /srv/sentinelforge/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
