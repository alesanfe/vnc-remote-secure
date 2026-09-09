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
    openssl \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies from requirements.txt
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpassword" | chpasswd && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Make scripts executable (recursive, matches modular subfolder layout)
RUN chmod +x /app/src/rpi-vnc-remote.sh && \
    find /app/src/lib -name '*.sh' -type f -exec chmod +x {} \; && \
    find /app/tests -name '*.sh' -type f -exec chmod +x {} \;

# Set default command
CMD ["/bin/bash"]
