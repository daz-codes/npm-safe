FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

# Create sandboxuser with writable home for npm cache
RUN useradd -m sandboxuser \
    && mkdir -p /sandbox /tmp \
    && chown sandboxuser:sandboxuser /sandbox

WORKDIR /sandbox
USER sandboxuser
