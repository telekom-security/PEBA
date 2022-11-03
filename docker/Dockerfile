FROM alpine:3.16 as builder

RUN apk -U --no-cache add \
    git \
    python3 \
    python3-dev && \
    mkdir -p /opt/peba && \
    cd /opt/peba && \
    git clone https://github.com/telekom-security/PEBA.git /opt/peba && \
    python3 -m venv peba-env && \
    . peba-env/bin/activate && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --upgrade -r requirements.txt


FROM alpine:3.16

RUN apk -U --no-cache add \
    python3 \
    py3-gunicorn && \
    adduser --disabled-password --shell /bin/ash --uid 2000 peba && \
    mkdir -p /opt/peba && \
    mkdir -p /var/run/peba && \
    chown peba:peba /var/run/peba

ENV PATH=/opt/peba/peba-env/bin:${PATH}

COPY --from=builder --chown=peba:peba /opt/peba/ /opt/peba/

RUN chown -R peba:peba /opt/peba

STOPSIGNAL SIGKILL

USER peba:peba

WORKDIR /opt/peba
CMD python3 peba-env/bin/gunicorn peba:app --workers=10 --bind=0.0.0.0:9922 --log-level warn --pid=/var/run/peba/gunicorn.pid --timeout 60 --max-requests 1000
