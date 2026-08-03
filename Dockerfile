FROM python:3.11-slim

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

# Entrypoint
ENTRYPOINT ["aegis"]
CMD ["--help"]
