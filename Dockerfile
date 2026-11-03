# syntax=docker/dockerfile:1

# Stage 1: Install Mermaid CLI in official Node.js image
FROM node:20-slim AS mermaid-builder
ENV PUPPETEER_SKIP_DOWNLOAD=true
RUN npm install -g @mermaid-js/mermaid-cli@11.4.2 \
    && npm cache clean --force

# Stage 2: Final runtime image
FROM python:3.12-slim

# Labels following OCI specifications
LABEL org.opencontainers.image.title="secdiagram" \
      org.opencontainers.image.description="Deterministic architecture, relationship, and security diagrams for Python repositories." \
      org.opencontainers.image.authors="secdiagram maintainers" \
      org.opencontainers.image.licenses="MIT"

# Install git, ca-certificates, and system Chromium for offline diagram rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    chromium \
    fonts-freefont-ttf \
    && rm -rf /var/lib/apt/lists/*

# Copy Node binary and Mermaid CLI from builder stage
COPY --from=node:20-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=mermaid-builder /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN chmod +x /usr/local/lib/node_modules/@mermaid-js/mermaid-cli/src/cli.js \
    && ln -sf /usr/local/lib/node_modules/@mermaid-js/mermaid-cli/src/cli.js /usr/local/bin/mmdc

# Configure Puppeteer to use system Chromium without sandbox inside Docker container
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Create Puppeteer and Mermaid config files for mmdc
RUN echo '{"args": ["--no-sandbox", "--disable-setuid-sandbox"]}' > /etc/puppeteer-config.json \
    && echo '{"maxTextSize": 5000000, "maxEdges": 2000}' > /etc/mermaid-config.json
ENV PUPPETEER_CONFIG=/etc/puppeteer-config.json \
    MERMAID_CONFIG=/etc/mermaid-config.json

# Create non-root user for container security
RUN useradd -u 10001 -m -s /bin/bash secdiagram \
    && mkdir -p /repo /app \
    && chown -R secdiagram:secdiagram /app /repo

WORKDIR /app

# Copy application source code
COPY . /app

# Install secdiagram package
RUN pip install --no-cache-dir .

# Switch to non-root user and target volume
USER secdiagram
WORKDIR /repo
VOLUME ["/repo"]

ENTRYPOINT ["secdiagram"]
CMD ["--dir", "."]
