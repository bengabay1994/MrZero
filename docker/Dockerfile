# MrZero Security Tools Container
# Contains all security scanning tools for MrZero agents

FROM ubuntu:22.04

LABEL maintainer="bengabay1994"
LABEL description="MrZero security scanning tools container"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install base dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    ruby \
    ruby-dev \
    openjdk-17-jdk \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up Python
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install uv for faster Python package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /tools

# ============================================
# Gitleaks - Secrets scanning
# ============================================
RUN GITLEAKS_VERSION=$(curl -sL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name' | sed 's/v//') && \
    ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" | tar xz -C /usr/local/bin gitleaks

# ============================================
# Trivy - Vulnerability scanning
# ============================================
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ============================================
# Bearer - Security and privacy scanning
# ============================================
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ============================================
# Opengrep (Semgrep fork) - Pattern-based analysis
# ============================================
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# ============================================
# Slither - Solidity smart contract analysis
# ============================================
RUN uv tool install slither-analyzer
RUN uv tool install solc-select
ENV PATH="/root/.local/bin:$PATH"
RUN solc-select install latest && solc-select use latest

# ============================================
# CodeQL - Semantic code analysis
# Note: CodeQL only provides linux64 (x86_64), skip on ARM64
# ============================================
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        mkdir -p /opt/codeql && \
        CODEQL_VERSION=$(curl -sL https://api.github.com/repos/github/codeql-action/releases/latest | jq -r '.tag_name') && \
        curl -sSL -o /tmp/codeql.tar.gz "https://github.com/github/codeql-action/releases/download/${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz" && \
        tar xzf /tmp/codeql.tar.gz -C /opt && \
        rm /tmp/codeql.tar.gz; \
    else \
        echo "CodeQL not available for $ARCH, skipping"; \
    fi
ENV PATH="/opt/codeql:$PATH"

# ============================================
# Joern - Code property graph analysis
# ============================================
RUN mkdir -p /opt/joern && \
    curl -sSL -o /tmp/joern.zip https://github.com/joernio/joern/releases/latest/download/joern-cli.zip && \
    unzip -q /tmp/joern.zip -d /opt/joern && \
    rm /tmp/joern.zip && \
    chmod +x /opt/joern/joern-cli/joern
ENV PATH="/opt/joern/joern-cli:$PATH"

# ============================================
# Linguist - Language detection
# ============================================
RUN gem install github-linguist

# ============================================
# Exploitation Tools
# ============================================

# pwntools - CTF framework and exploit development
RUN uv tool install pwntools

# Ropper - ROP gadget finder
RUN uv tool install ropper

# one_gadget - Find one-shot RCE gadgets in libc
RUN gem install one_gadget

# ============================================
# Cleanup
# ============================================
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory for scanning
WORKDIR /workspace

# Default entrypoint - can be overridden
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'MrZero Tools Container - use specific tool commands'"]
