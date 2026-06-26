# syntax=docker/dockerfile:1

FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --system --gid 10001 pyhttpd \
    && useradd --system --uid 10001 --gid pyhttpd \
       --home-dir /srv --shell /usr/sbin/nologin pyhttpd

COPY --from=build /opt/venv /opt/venv

RUN mkdir -p /srv && chown -R pyhttpd:pyhttpd /srv

USER pyhttpd
WORKDIR /srv

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

CMD ["pyhttpd", "--host", "0.0.0.0", "--port", "8080", "--directory", "/srv"]
