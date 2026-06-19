FROM python:3-alpine
RUN apk add --no-cache nftables

RUN mkdir -p /etc/portkey /var/run/portkey /var/log/portkey && \
    chown nobody:nogroup /var/run/portkey /var/log/portkey

COPY requirements.txt /opt/portkey/
RUN pip install --no-cache-dir -r /opt/portkey/requirements.txt

COPY server/   /opt/portkey/server/
COPY protocol.py /opt/portkey/
COPY portkey.toml /opt/portkey/

ENV PORTKEY_CONFIG=/opt/portkey/portkey.toml

WORKDIR /opt/portkey

ENTRYPOINT ["python3", "-m", "server.main", "--config", "/opt/portkey/portkey.toml"]
