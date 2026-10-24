"""二阶段 Docker 的时间预算与失败分类（唯一事实来源）。

此前的两个常量（构建 300 秒、执行 120 秒）散落在执行器里，失败文本也不区分
“构建超时”与“容器执行超时”，重试循环只能笼统地说“执行超时”。这里把两者
收敛成一份策略：

* 时间预算按用途分开，可用环境变量覆盖，非法值明确报错而不是静默回落；
* 失败分类是字符串常量，执行器、结果收集器和重试循环共用同一套词汇；
* “是否值得让模型重写测试”由分类推导，不再由每个调用点各自判断。
"""

from dataclasses import dataclass, fields
import os

# 失败分类。执行器写入 ``DockerExecutionResult.failure_kind``，结果收集器据此
# 决定 details 前缀与提示，重试循环据此决定是否继续请求模型。
STAGING = "staging"              # 生成文件写入/仓库预置失败：模型可能能修
TOOLCHAIN = "toolchain"          # 共享工具链镜像不可用：宿主问题
IMAGE = "image"                  # 基础镜像缺失且无法拉取（注册表/网络）：宿主问题
ENVIRONMENT = "environment"      # 守护进程/代理不可用：宿主问题
BUILD = "build"                  # 构建失败（编译、依赖、Dockerfile）：模型可能能修
BUILD_TIMEOUT = "build_timeout"  # 构建超时：网络或镜像过大，重写测试无用
RUN = "run"                      # 容器运行失败（未产出有效结果）：模型可能能修
RUN_TIMEOUT = "run_timeout"      # 容器执行超时：重写测试无用
CLEANUP = "cleanup"              # 资源回收失败：宿主问题

# 非模型可修复的失败：重试只会重复消耗配额与时间。
# STAGING 不在此列：暂存失败多来自模型选用的文件名或依赖清单冲突，换一份生成
# 结果确实可能成功，因此它仍值得一次带错误反馈的重试（执行器的注释即此意图）。
NOT_MODEL_FIXABLE = frozenset({
    TOOLCHAIN, IMAGE, ENVIRONMENT, BUILD_TIMEOUT, RUN_TIMEOUT, CLEANUP,
})

# 结果收集器与运维提示共用的分类说明。
FAILURE_LABELS = {
    STAGING: "测试文件准备失败",
    TOOLCHAIN: "Docker 工具链不可用",
    IMAGE: "Docker 基础镜像不可用",
    ENVIRONMENT: "Docker 环境不可用",
    BUILD: "Docker 构建失败",
    BUILD_TIMEOUT: "Docker 构建超时",
    RUN: "容器执行失败",
    RUN_TIMEOUT: "容器执行超时",
    CLEANUP: "Docker 资源清理失败",
}

DEFAULT_BUILD_TIMEOUT = 900       # 秒；首次构建需下载语言依赖
DEFAULT_RUN_TIMEOUT = 120         # 秒；容器内执行
DEFAULT_TOOLCHAIN_TIMEOUT = 1800  # 秒；工具链镜像一次性构建（含基础镜像拉取）
DEFAULT_PULL_TIMEOUT = 600        # 秒；基础镜像拉取（由守护进程完成）

_ENV_NAMES = {
    "build_timeout": "VULSCAN_DOCKER_BUILD_TIMEOUT",
    "run_timeout": "VULSCAN_DOCKER_RUN_TIMEOUT",
    "toolchain_timeout": "VULSCAN_DOCKER_TOOLCHAIN_TIMEOUT",
    "pull_timeout": "VULSCAN_DOCKER_PULL_TIMEOUT",
}

_DEFAULTS = {
    "build_timeout": DEFAULT_BUILD_TIMEOUT,
    "run_timeout": DEFAULT_RUN_TIMEOUT,
    "toolchain_timeout": DEFAULT_TOOLCHAIN_TIMEOUT,
    "pull_timeout": DEFAULT_PULL_TIMEOUT,
}


@dataclass(frozen=True)
class BuildPolicy:
    """一次二阶段运行的时间预算，单位秒，均为正整数。"""

    build_timeout: int = DEFAULT_BUILD_TIMEOUT
    run_timeout: int = DEFAULT_RUN_TIMEOUT
    toolchain_timeout: int = DEFAULT_TOOLCHAIN_TIMEOUT
    pull_timeout: int = DEFAULT_PULL_TIMEOUT

    @classmethod
    def from_environment(cls, environ=None, **overrides) -> "BuildPolicy":
        """读取环境变量；``overrides`` 优先（供测试与显式配置使用）。"""
        env = os.environ if environ is None else environ
        values = {}
        for field in fields(cls):
            name = _ENV_NAMES[field.name]
            raw = env.get(name)
            if raw is None or not raw.strip():
                values[field.name] = _DEFAULTS[field.name]
                continue
            try:
                value = int(raw.strip())
            except ValueError:
                raise ValueError(f"{name} 必须是正整数秒数，当前为 {raw!r}") from None
            if value <= 0:
                raise ValueError(f"{name} 必须是正整数秒数，当前为 {value}")
            values[field.name] = value
        values.update(overrides)
        return cls(**values)

    def retry_allowed(self, failure_kind: str | None) -> bool:
        """该失败是否值得让模型重写测试后重跑。"""
        return failure_kind not in NOT_MODEL_FIXABLE
