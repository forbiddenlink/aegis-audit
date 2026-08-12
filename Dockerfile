# Pinned by digest for reproducible builds (tag = python:3.11-slim).
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

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
