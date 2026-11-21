# OpenCanary low-interaction honeypot: fake services that log every connection and login attempt.
# No real shell, file system or database is ever exposed.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev \
    && pip install --no-cache-dir opencanary==0.9.10 \
    && apt-get purge -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY opencanary.conf log404.tac /etc/opencanaryd/
RUN mkdir -p /var/log/opencanary && chown nobody:nogroup /var/log/opencanary
# Binds the low ports as root, then twistd drops to nobody for the rest of its life
CMD ["twistd", "-noy", "/etc/opencanaryd/log404.tac", "--pidfile=", "--uid=nobody", "--gid=nogroup"]
