FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Create a working directory
WORKDIR /app

# Initial system updates and essential tools
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    pkg-config \
    sudo \
    tcpdump \
    tmux \
    vim \
    netcat-openbsd \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Deminimize Ubuntu
RUN yes | unminimize

# Create a non-root user
RUN useradd -m -s /bin/bash developer

# Give developer user sudo access without password
RUN echo "developer ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/developer && \
    chmod 0440 /etc/sudoers.d/developer

# Switch to developer user
USER developer

# Create .cargo directory for developer user
RUN mkdir -p /home/developer/.cargo

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/home/developer/.cargo/bin:${PATH}"

# Copy all project files
# To run the container with the current directory mounted:
# docker run -it -v $(pwd):/home/developer/app <image-name>
VOLUME ["/home/developer/app"]

# # Compile tcp-dump
WORKDIR /home/developer/app/tcp-server

# (Optional) Uncomment and adjust if you need to compile any C code
# RUN gcc -o tcp-dump tcp-dump.c

# (Optional) Other steps like exposing ports or starting scripts can remain commented out.
# EXPOSE 8080
# CMD ["./tmux-setup.sh"]