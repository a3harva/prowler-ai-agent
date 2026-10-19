# One image; api and worker differ only by the command docker-compose runs.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.6.16 /uv /uvx /usr/local/bin/

# The worker launches Prowler as a sibling container over the host Docker
# socket (see app/integrations/prowler_runner.py) — it shells out to the
# `docker` CLI itself rather than a Python SDK, mirroring the manual command
# it's modelled on. Debian trixie's `docker.io` package pulls in dockerd but,
# on this base image, no /usr/bin/docker client at all (verified: `dpkg -L
# docker.io` lists no binary) — so the static client binary is fetched
# directly from Docker instead, matching the daemon's own moby lineage.
# WeasyPrint (report_pdf.py) loads Pango/HarfBuzz/fontconfig via cffi at
# import time, not at `uv sync` time — a missing native lib here fails
# silently until the first PDF render. Verified against the exact
# weasyprint==69.0 pinned in uv.lock: no cairo, no gdk-pixbuf needed (that
# version renders via its own pydyf/pillow, not cairo — earlier WeasyPrint
# releases needed more).
#
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         curl ca-certificates \
         libglib2.0-0t64 libpango-1.0-0 libpangoft2-1.0-0 \
         libharfbuzz0b libharfbuzz-subset0 libfontconfig1 fontconfig fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         amd64) docker_arch=x86_64 ;; \
         arm64) docker_arch=aarch64 ;; \
         *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${docker_arch}/docker-26.1.4.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm /tmp/docker.tgz \
    && docker --version

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
