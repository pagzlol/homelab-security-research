# =============================================================================
# ningi-recon — Lean attack surface scanner
# Built on Ubuntu 24.04 to match the rest of the ningi stack
# Tools: nmap, whatweb, nuclei, amass, curl, dig, python3, supercronic
# =============================================================================

FROM ubuntu:24.04

LABEL maintainer="ningi homelab"
LABEL description="Attack surface monitoring scanner"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

# --- System packages ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nmap-common \
    whatweb \
    curl \
    wget \
    dnsutils \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    unzip \
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Install Go ---
RUN curl -fsSL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    | tar -C /usr/local -xz

# --- Install supercronic (cron for containers) ---
RUN curl -fsSL https://github.com/aptible/supercronic/releases/latest/download/supercronic-linux-amd64 \
    -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic

# --- Install Nuclei ---
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates -silent || true

# --- Install Amass ---
RUN go install -v github.com/owasp-amass/amass/v4/...@master || \
    ( curl -fsSL $(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest \
        | jq -r '.assets[] | select(.name | contains("linux_amd64")) | .browser_download_url') \
        -o /tmp/amass.zip \
    && unzip /tmp/amass.zip -d /tmp/amass \
    && mv /tmp/amass/*/amass /usr/local/bin/amass \
    && rm -rf /tmp/amass* )

# --- Python packages ---
RUN pip3 install --break-system-packages \
    requests \
    shodan

# --- Copy recon scripts and crontab ---
RUN mkdir -p /recon /scans
COPY monitor.sh portscan.sh webscan.sh dnsscan.sh crontab /recon/
RUN chmod +x /recon/*.sh

WORKDIR /recon

CMD ["/usr/local/bin/supercronic", "/recon/crontab"]
