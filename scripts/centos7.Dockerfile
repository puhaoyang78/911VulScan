# CentOS 7 keeps its system Python/glibc. Only this application uses these tools.
FROM node:22-bookworm-slim AS node
FROM golang:1.26-alpine AS go
FROM docker:26.1.4-cli AS dockercli
FROM ubuntu:24.04

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUNBUFFERED=1 DOCKER_HOST=unix:///var/run/docker.sock
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
       ca-certificates curl git python3 python3-venv python3-dev build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/911VulScan
COPY --from=node /usr/local/ .tools/node/
COPY --from=go /usr/local/go/ .tools/go/
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/ /usr/local/lib/docker/cli-plugins/
COPY apps/vulscan-cli/ apps/vulscan-cli/
COPY libs/vulscan-core/ libs/vulscan-core/
COPY config/languages.json config/models.json config/
COPY scripts/install-deployment.sh scripts/check-deployment.py scripts/
ENV PATH=/opt/911VulScan/.tools/go/bin:/opt/911VulScan/.tools/node/bin:$PATH
RUN sh scripts/install-deployment.sh \
    && .venv/bin/python scripts/check-deployment.py --root /opt/911VulScan
LABEL org.911vulscan.deployment="centos7"
ENTRYPOINT ["/opt/911VulScan/bin/vulscan"]
CMD ["serve", "--addr", "127.0.0.1:8080"]
