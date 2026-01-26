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
RUN GITLEAKS_URL=$(curl -sL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | \
    grep "browser_download_url.*linux_x64.tar.gz" | cut -d '"' -f 4) && \
    curl -sSL "$GITLEAKS_URL" | tar xz -C /usr/local/bin gitleaks

# ============================================
# Trivy - Vulnerability scanning
# ============================================
RUN TRIVY_URL=$(curl -sL https://api.github.com/repos/aquasecurity/trivy/releases/latest | \
    grep "browser_download_url.*Linux-64bit.tar.gz" | grep -v ".sig" | head -1 | cut -d '"' -f 4) && \
    curl -sSL "$TRIVY_URL" | tar xz -C /usr/local/bin trivy

# ============================================
# Bearer - Security and privacy scanning
# ============================================
RUN BEARER_URL=$(curl -sL https://api.github.com/repos/Bearer/bearer/releases/latest | \
    grep "browser_download_url.*linux_amd64.tar.gz" | cut -d '"' -f 4) && \
    curl -sSL "$BEARER_URL" | tar xz -C /usr/local/bin bearer

# ============================================
# Opengrep (Semgrep fork) - Pattern-based analysis
# ============================================
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# ============================================
# Slither - Solidity smart contract analysis
# ============================================
RUN uv pip install --system slither-analyzer solc-select
RUN solc-select install latest && solc-select use latest

# ============================================
# CodeQL - Semantic code analysis
# ============================================
RUN mkdir -p /opt/codeql && \
    curl -sSL -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip && \
    unzip -q /tmp/codeql.zip -d /opt && \
    rm /tmp/codeql.zip
ENV PATH="/opt/codeql:$PATH"

# ============================================
# Joern - Code property graph analysis
# ============================================
RUN mkdir -p /opt/joern && \
    JOERN_URL=$(curl -sL https://api.github.com/repos/joernio/joern/releases/latest | \
    grep "browser_download_url.*joern-cli.zip" | cut -d '"' -f 4) && \
    curl -sSL "$JOERN_URL" -o /tmp/joern.zip && \
    unzip -q /tmp/joern.zip -d /opt/joern && \
    rm /tmp/joern.zip && \
    chmod +x /opt/joern/joern-cli/joern
ENV PATH="/opt/joern/joern-cli:$PATH"

# ============================================
# Infer - Static analysis (Facebook)
# ============================================
RUN INFER_URL=$(curl -sL https://api.github.com/repos/facebook/infer/releases/latest | \
    grep "browser_download_url.*linux-x86_64.*tar.xz" | cut -d '"' -f 4) && \
    curl -sSL "$INFER_URL" | tar xJ -C /opt && \
    ln -s /opt/infer-*/bin/infer /usr/local/bin/infer

# ============================================
# Linguist - Language detection
# ============================================
RUN gem install github-linguist

# ============================================
# Tree-sitter - Syntax parsing
# ============================================
RUN uv pip install --system tree-sitter

# ============================================
# Cleanup
# ============================================
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory for scanning
WORKDIR /workspace

# Default entrypoint - can be overridden
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'MrZero Tools Container - use specific tool commands'"]
