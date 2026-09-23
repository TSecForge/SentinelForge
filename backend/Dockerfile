FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/sentinelforge

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Rule packs, sample data and collector are read at runtime (RULE_PATHS, demo templates).
COPY backend/app backend/app
COPY detection-rules detection-rules
COPY custom-rules custom-rules
COPY sample-data sample-data
COPY collectors collectors
COPY plugins plugins

RUN useradd --system --uid 10001 sentinelforge && chown -R sentinelforge /srv/sentinelforge
USER sentinelforge
WORKDIR /srv/sentinelforge/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
