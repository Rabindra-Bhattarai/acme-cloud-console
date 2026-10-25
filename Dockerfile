# Acme Cloud Console -- INTENTIONALLY VULNERABLE lab.
# RUN ONLY IN A DISPOSABLE, ISOLATED CONTAINER/VM. The finish is real RCE:
# whoever completes it can run commands as this container's unprivileged
# 'player' user. Keep it off any machine/network you care about.
FROM python:3.12-slim

# Unprivileged, neutral identity: `whoami` inside shows 'player', never a real
# account, and the RCE is confined to this container.
RUN useradd --create-home --uid 10001 player
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R player:player /app
USER player

ENV ACME_HOST=0.0.0.0 ACME_PORT=5000
EXPOSE 5000
CMD ["python", "app.py"]
