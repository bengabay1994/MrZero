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
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar xz -C /usr/local/bin gitleaks

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
    curl -sSL -o /tmp/joern.zip https://github.com/joernio/joern/releases/latest/download/joern-cli.zip && \
    unzip -q /tmp/joern.zip -d /opt/joern && \
    rm /tmp/joern.zip && \
    chmod +x /opt/joern/joern-cli/joern
ENV PATH="/opt/joern/joern-cli:$PATH"

# ============================================
# Infer - Static analysis (Facebook)
# ============================================
# Note: Infer doesn't support /releases/latest/download/ pattern due to version in filename
# Using specific version to avoid API rate limits
RUN curl -sSL -o /tmp/infer.tar.xz https://github.com/facebook/infer/releases/download/v1.2.0/infer-linux-x86_64-v1.2.0.tar.xz && \
    tar xJf /tmp/infer.tar.xz -C /opt && \
    rm /tmp/infer.tar.xz && \
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
