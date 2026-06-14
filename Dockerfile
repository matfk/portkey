FROM python:3-alpine

RUN pip install --no-cache-dir pynacl

COPY portkeyd.py /usr/local/bin/portkeyd
RUN chmod +x /usr/local/bin/portkeyd

ENTRYPOINT ["portkeyd"]
