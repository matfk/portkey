FROM python:3-alpine

RUN pip install --no-cache-dir pynacl

COPY server/ /opt/portkey/server/

ENTRYPOINT ["python3", "-m", "server.main"]
