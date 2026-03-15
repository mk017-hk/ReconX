FROM python:3.11-slim

LABEL maintainer="mk017-hk"
LABEL description="ReconX — All-in-one Reconnaissance & Pentesting Toolkit"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies first (layer caching)
COPY pyproject.toml ./
COPY reconx/__init__.py reconx/__init__.py
RUN pip install --no-cache-dir -e .

# Copy rest of source
COPY . .

# Create reports output directory
RUN mkdir -p /reports

ENTRYPOINT ["reconx"]
CMD ["--help"]
