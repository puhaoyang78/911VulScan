"""Docker 构建环境：代理、镜像供应、时间预算与预检。

二阶段为每条发现构建一个镜像。历史上，四件“宿主环境”的事和“单条发现的构建”
纠缠在同一个函数里：

* 构建如何访问网络（直连还是代理）；
* 编译器工具链是否需要为每条发现重新下载一次；
* 基础镜像是否已在本机（拉取由守护进程完成，构建代理管不到）；
* 一次构建允许多久、失败到底意味着什么。

它们各自独立演化，导致一次网络抖动会让整批发现连续超时，且错误文本无法区分
“构建超时”和“容器执行超时”。这里把它们拆成独立模块，执行器只负责按顺序编排：

``proxy``      代理校验、本机回环代理的桥接中继、构建参数生成
``images``     本机镜像清单与按需拉取（含注册表故障识别）
``policy``     时间预算与失败分类（唯一事实来源）
``toolchain``  共享工具链镜像的构建与复用（一次构建，多发现复用）
``preflight``  在花费任何模型调用之前快速失败

导入本包不产生 Docker 调用。
"""

from utilities.docker_build.errors import DockerBuildEnvironmentError
from utilities.docker_build.images import (
    PullResult,
    available_images,
    dockerfile_bases,
    ensure_base_images,
    is_registry_failure,
)
from utilities.docker_build.policy import (
    BUILD,
    BUILD_TIMEOUT,
    CLEANUP,
    ENVIRONMENT,
    FAILURE_LABELS,
    IMAGE,
    NOT_MODEL_FIXABLE,
    RUN,
    RUN_TIMEOUT,
    STAGING,
    TOOLCHAIN,
    BuildPolicy,
)
from utilities.docker_build.proxy import (
    build_proxy_arguments,
    describe_proxy,
    parse_docker_proxy,
    probe_proxy,
)
from utilities.docker_build.toolchain import (
    Toolchain,
    ensure_toolchain,
    native_toolchain,
    render_native_dockerfile,
)

__all__ = [
    "BuildPolicy",
    "BUILD",
    "BUILD_TIMEOUT",
    "CLEANUP",
    "DockerBuildEnvironmentError",
    "ENVIRONMENT",
    "FAILURE_LABELS",
    "IMAGE",
    "NOT_MODEL_FIXABLE",
    "PullResult",
    "RUN",
    "RUN_TIMEOUT",
    "STAGING",
    "TOOLCHAIN",
    "Toolchain",
    "available_images",
    "build_proxy_arguments",
    "describe_proxy",
    "dockerfile_bases",
    "ensure_base_images",
    "ensure_toolchain",
    "is_registry_failure",
    "native_toolchain",
    "parse_docker_proxy",
    "probe_proxy",
    "render_native_dockerfile",
]
