# ============================================================================
# DOCKERFILE FOR TEST ENVIRONMENT
# ============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    bash \
    sudo \
    wget \
    curl \
    git \
    shellcheck \
    lsof \
    iproute2 \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpassword" | chpasswd && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Make scripts executable
RUN chmod +x /app/src/rpi-vnc-remote.sh && \
    chmod +x /app/src/lib/*.sh && \
    chmod +x /app/tests/*.sh && \
    chmod +x /app/tests/unit/*.sh && \
    chmod +x /app/tests/integration/*.sh && \
    chmod +x /app/tests/security/*.sh

# Set default command
CMD ["/bin/bash"]
