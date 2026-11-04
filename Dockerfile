# Stage 1: Install Mermaid CLI in official Node.js image
FROM node:26-slim@sha256:e4db4c914bf8ad241bd24804fc25d272d89bad97e68cdc8a1414862790a02c39 AS mermaid-builder
ENV PUPPETEER_SKIP_DOWNLOAD=true
WORKDIR /opt/mermaid
COPY docker/mermaid/package.json docker/mermaid/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && npm cache clean --force

# Stage 2: Final runtime image
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

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

# Copy Node binary and locked Mermaid CLI dependencies from the builder stage
COPY --from=mermaid-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=mermaid-builder /opt/mermaid/node_modules /opt/mermaid/node_modules
RUN ln -sf /opt/mermaid/node_modules/.bin/mmdc /usr/local/bin/mmdc

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
