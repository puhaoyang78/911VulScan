FROM golang:1.26-alpine
WORKDIR /test
# 固定所选工具链，不能让依赖下载隐式升级目标运行时。
ENV GOTOOLCHAIN=local GOCACHE=/opt/openant-go-build-cache GOMODCACHE=/go/pkg/mod
COPY . .
# 源文件与 import 布局准备完成后，在构建期初始化模块、下载依赖并编译。
# 库包目标须先 RUN mkdir -p target && mv <目标文件.go> target/，根目录不留副本。
RUN go mod init openant-test && go mod tidy
RUN go build -mod=readonly -o /test/test_exploit .
# /tmp 在运行时由新 tmpfs 覆盖，编译产物和模块缓存不得依赖它。
CMD ["./test_exploit"]
