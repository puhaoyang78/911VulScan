"""CLI entry point: python -m utilities.dynamic_tester pipeline_output.json [--output-dir DIR]"""

import argparse

from utilities.dynamic_tester import run_dynamic_tests


def main():
    parser = argparse.ArgumentParser(
        description="使用 Docker 容器执行动态漏洞验证",
    )
    parser.add_argument(
        "pipeline_output",
        help="静态分析流程产生的 pipeline_output.json 路径",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="结果输出目录（默认与输入文件同目录）",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="每项发现出现 ERROR 后的最大重试次数（默认 3）",
    )

    parser.add_argument("--repo-path", default=None, help="真实目标仓库路径（C/C++ 验证必需）")
    from utilities.docker_build import parse_docker_proxy
    parser.add_argument("--docker-proxy", type=parse_docker_proxy, help="可选构建代理：http://IP:端口")

    args = parser.parse_args()

    from utilities.docker_build import DockerBuildEnvironmentError
    try:
        results = run_dynamic_tests(
            args.pipeline_output, args.output_dir,
            max_retries=args.max_retries, repo_path=args.repo_path,
            docker_proxy=args.docker_proxy,
        )
    except DockerBuildEnvironmentError as exc:
        # 宿主环境问题与被测代码无关：一行说明即可，不需要堆栈。
        raise SystemExit(f"动态测试环境不可用：{exc}") from None

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n" + "=" * 50)
    print("动态测试汇总")
    print("=" * 50)
    for status in ["CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"]:
        if status in counts:
            print(f"  {status}: {counts[status]}")
    print(f"  总计： {len(results)}")
    print("=" * 50)


if __name__ == "__main__":
    main()
