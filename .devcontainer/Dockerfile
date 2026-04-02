# Pin to immutable digest - never a mutable tag
# Update this digest deliberately as part of the dep review process
FROM golang:1.25-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa

RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    binutils-gold \
    bash \
    curl \
    bind-tools \
    ipset \
    iptables-legacy \
    jq \
    sudo

# Go tools baked in at exact commit SHAs - tags are mutable, SHAs are not
# SHA corresponds to: gopls@v0.21.1
RUN go install golang.org/x/tools/gopls@5c4433be420451410e8cfd968eda32a818dac087 && \
    # SHA corresponds to: dlv@v1.26.1
    go install github.com/go-delve/delve/cmd/dlv@5a5f35e1588307435d7734175036eb82b0a86a9a && \
    # SHA corresponds to: goimports@v0.43.0
    go install golang.org/x/tools/cmd/goimports@24a8e95f9d7ae2696f66314da5e50c0d98ccaa90 && \
    # SHA corresponds to: golangci-lint@v1.64.8
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@8b37f14162043f908949f1b363d061dc9ba713c0 && \
    # SHA corresponds to: govulncheck@v1.1.4
    go install golang.org/x/vuln/cmd/govulncheck@d1f380186385b4f64e00313f31743df8e4b89a77 && \
    # SHA corresponds to: osv-scanner@v1.9.2
    go install github.com/google/osv-scanner/cmd/osv-scanner@1e295ee11c5e107886e58bacb04228325082146f

WORKDIR /app

# Pre-download deps - cached layer, only re-runs if go.mod/go.sum changes
COPY go.mod go.sum ./
RUN go mod download -x

ENV GOFLAGS=-mod=readonly

## v2
# Firewall scripts - intentionally last: changes here only invalidate these cheap layers
COPY scripts/init-firewall.sh /usr/local/bin/
COPY scripts/refresh-firewall.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/refresh-firewall.sh && \
    echo "$(whoami) ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" \
    > /etc/sudoers.d/tyk-firewall && \
    chmod 0440 /etc/sudoers.d/tyk-firewall

# Cron job to re-resolve CDN-backed domains every 30 minutes
RUN echo "*/30 * * * * /usr/local/bin/refresh-firewall.sh >> /var/log/firewall-refresh.log 2>&1" \
    | crontab -
