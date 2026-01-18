# MrZero Toolbox - Security Analysis Tools Container
# This container provides SAST and code analysis tools for MrZero CLI

FROM ubuntu:22.04

LABEL maintainer="MrZero Team"
LABEL description="MrZero Toolbox - Security analysis tools container"
LABEL version="1.0"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Basic utilities
    curl \
    wget \
    git \
    ca-certificates \
    gnupg \
    unzip \
    # Ruby for Linguist
    ruby \
    ruby-dev \
    build-essential \
    cmake \
    pkg-config \
    libicu-dev \
    # Required for rugged gem (linguist dependency)
    libgit2-dev \
    libssl-dev \
    zlib1g-dev \
    # Clean up
    && rm -rf /var/lib/apt/lists/* \
    # Create symlink for gmake (required by rugged gem)
    && ln -sf /usr/bin/make /usr/bin/gmake

# Install Opengrep using official install script
# https://github.com/opengrep/opengrep
RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Install GitHub Linguist
RUN gem install github-linguist --no-document

# Create workspace directory
WORKDIR /workspace

# Copy entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command shows help
CMD ["--help"]
