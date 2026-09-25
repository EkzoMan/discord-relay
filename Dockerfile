FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    RELAY_DB_PATH=/data/relay.db \
    RELAY_CONFIG_PATH=/data/config.json

# Non-root runtime user.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin relay

WORKDIR /srv/discord_relay

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Persistent data location: SQLite DB (users/sessions/relays) + legacy config.
RUN mkdir -p /data && chown -R relay:relay /data /srv/discord_relay

USER relay
EXPOSE 8000

# Shell form so ${PORT} from the environment is honoured; `exec` replaces the
# shell with uvicorn so it runs as PID 1 and receives SIGTERM on `docker stop`
# (without it, the shell swallows shutdown signalling and the lifespan handler
# never runs).
CMD exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
