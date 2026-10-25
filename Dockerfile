# Reproducible build. Two properties are load-bearing:
#   1. the base image is pinned BY DIGEST, not by tag - python:3.12-slim is a
#      moving target and a tag pin is not a pin;
#   2. dependencies install from a hash-checked, fully-resolved lock file with
#      --no-deps, so pip resolves nothing at build time.
#
# Refresh the digest deliberately:
#   docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
ARG PYTHON_IMAGE=python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Own virtualenv so the runtime stage inherits no build tooling.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.lock ./
# --require-hashes: every artefact is verified against poetry.lock's hashes.
# --no-deps: the file is already fully resolved; pip must not add to it.
# all was scanned with safety scan
RUN pip install --require-hashes --no-deps -r requirements.lock

FROM ${PYTHON_IMAGE} AS runtime

RUN groupadd --system mcp \
    && useradd --system --gid mcp --home-dir /app --shell /usr/sbin/nologin mcp

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    CONFIG_PATH=/app/config/mcp-server-config.yaml

COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --chown=mcp:mcp src ./src
# Reviewed security policy. Baked in deliberately - see README section 2.
# Do not mount over this path and do not repoint CONFIG_PATH at mutable storage.
COPY --chown=mcp:mcp config/mcp-server-config.yaml ./config/mcp-server-config.yaml

USER mcp
EXPOSE 8000

# One worker is deliberate: rate, concurrency and readiness-cache state are
# process-local. Platform probes own liveness/readiness; do not add HEALTHCHECK.
CMD ["python", "-m", "src.main"]
