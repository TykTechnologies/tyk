# Pin to immutable digest - never a mutable tag
# Update this digest deliberately as part of the dep review process
FROM golang:1.25-alpine@sha256:<pinned-digest>

RUN apk add --no-cache \
    git=2.47.2-r0 \
    make=4.4.1-r2 \
    gcc=14.2.0-r4 \
    musl-dev=1.2.5-r8 \
    bash=5.2.37-r0 \
    curl=8.11.1-r0 \
    bind-tools=9.18.31-r0 \
    ipset=7.22-r0 \
    iptables=1.8.11-r0 \
    jq=1.7.1-r0 \
    sudo=1.9.16-r0

# Go tools baked in at exact commit SHAs - tags are mutable, SHAs are not
# SHA corresponds to: gopls@v0.17.1
RUN go install golang.org/x/tools/gopls@18f6663b1eafb31b986cdf22a4f7864922976448 && \
    # SHA corresponds to: dlv@v1.24.0
    go install github.com/go-delve/delve/cmd/dlv@0b7bffc7d40411f8361e10009e73fb9c9b318fb6 && \
    # SHA corresponds to: goimports@v0.29.0
    go install golang.org/x/tools/cmd/goimports@1743d1a7ef4ad2eb78666f099522a07b02bca878 && \
    # SHA corresponds to: golangci-lint@v1.62.2
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@89476e7a1eaa0a8a06c17343af960a5fd9e7edb7 && \
    # SHA corresponds to: govulncheck@v1.1.3
    go install golang.org/x/vuln/cmd/govulncheck@4ea4418106cea3bb2c9aa098527c924e9e1fbbb4 && \
    # SHA corresponds to: osv-scanner@v1.9.1
    go install github.com/google/osv-scanner/cmd/osv-scanner@b13f37e1a1e4cb98556c1d34cd3256a876929be1

WORKDIR /app

# Pre-download deps - cached layer, only re-runs if go.mod/go.sum changes
COPY go.mod go.sum ./
RUN go mod download -x

# Firewall scripts
COPY .devcontainer/init-firewall.sh /usr/local/bin/
COPY .devcontainer/refresh-firewall.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/refresh-firewall.sh && \
    echo "$(whoami) ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" \
    > /etc/sudoers.d/tyk-firewall && \
    chmod 0440 /etc/sudoers.d/tyk-firewall

# Cron job to re-resolve CDN-backed domains every 30 minutes
RUN echo "*/30 * * * * /usr/local/bin/refresh-firewall.sh >> /var/log/firewall-refresh.log 2>&1" \
    | crontab -

ENV GOFLAGS=-mod=readonly
