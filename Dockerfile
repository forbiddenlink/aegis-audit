# Pinned by digest for reproducible builds (tag = python:3.11-slim).
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /app

# Install system dependencies (npm for node dependency checks, git for scans)
RUN apt-get update && apt-get install -y --no-install-recommends \
    npm \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole project BEFORE installing: the build backend (hatchling) reads
# README.md at metadata-generation time, so `pip install` fails if only
# pyproject.toml is present. This is why the previous two-stage COPY was broken.
COPY . .

RUN pip install --no-cache-dir .

# Drop root: the scanner never needs privilege, and running as root turns any
# parser/dependency bug into a container-escape primitive (trivy DS-0002). Scan
# output goes to the working directory, so run from a mounted, writable volume,
# e.g. `docker run -v "$PWD:/work" -w /work aegis audit .`.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Entrypoint
ENTRYPOINT ["aegis"]
CMD ["--help"]
