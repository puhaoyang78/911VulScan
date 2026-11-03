# CentOS 7 keeps its system Python/glibc. Only this application uses these tools.
FROM m.daocloud.io/docker.io/library/node:22-bookworm-slim AS node
FROM m.daocloud.io/docker.io/library/golang:1.26-alpine AS go
FROM m.daocloud.io/docker.io/library/docker:26.1.4-cli AS dockercli
FROM m.daocloud.io/docker.io/library/ubuntu:24.04

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUNBUFFERED=1 DOCKER_HOST=unix:///var/run/docker.sock \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    NPM_CONFIG_REGISTRY=https://registry.npmmirror.com \
    NPM_CONFIG_REPLACE_REGISTRY_HOST=always \
    GOPROXY=https://goproxy.cn GOSUMDB=sum.golang.google.cn
# Only the container's Ubuntu sources are replaced; signed package checks remain enabled.
RUN sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
      -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
      /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
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
CMD ["serve", "--addr", "0.0.0.0:8080"]
