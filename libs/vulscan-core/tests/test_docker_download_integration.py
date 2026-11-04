"""显式启用的真实下载验收；受控故障来自不可连接的国内源，不伪造下载成功。

VULSCAN_DOCKER_DOWNLOAD_TESTS=1 VULSCAN_TEST_PROXY=http://127.0.0.1:7890 \
    pytest tests/test_docker_download_integration.py -v -s
不调用模型；只删除本测试创建的精确镜像标签，保留共享基础镜像与构建缓存。
"""
from dataclasses import replace
import json
import os
import uuid

import pytest

from utilities.docker_build import downloads, images
from utilities.docker_build.dependencies import ensure_dependency_image, plan_for_repository
from utilities.docker_build.toolchain import ensure_toolchain, native_toolchain
from utilities.dynamic_tester.docker_executor import _run_command

pytestmark = pytest.mark.skipif(os.environ.get('VULSCAN_DOCKER_DOWNLOAD_TESTS') != '1',
                               reason='requires explicit real Docker network opt-in')


def checked(argv, **kwargs):
    result = _run_command(argv, **kwargs)
    assert result[2] == 0 and not result[3], '\n'.join((repr(argv), result[0], result[1]))
    return result[0].strip()


@pytest.mark.parametrize('language', ['python','node','go','c'])
@pytest.mark.parametrize('fail_domestic', [False, True], ids=['domestic','proxy-takeover'])
def test_real_dependency_build_and_cache(tmp_path, monkeypatch, language, fail_domestic):
    proxy = os.environ.get('VULSCAN_TEST_PROXY')
    assert proxy, 'Real proxy takeover requires VULSCAN_TEST_PROXY=http://IP:port'
    calls, output = [], []
    def run(argv, **kw):
        calls.append(argv)
        result = _run_command(argv, **kw)
        output.extend(result[:2])
        return result
    if fail_domestic:
        # The real package manager hits a refused TCP endpoint, then production
        # build_with_downloads must switch to official servers via the real proxy.
        prefix = downloads._PREFIX
        for host in ('pypi.tuna.tsinghua.edu.cn','registry.npmmirror.com',
                     'goproxy.cn','mirrors.tuna.tsinghua.edu.cn','mirrors.aliyun.com'):
            prefix = prefix.replace(host,'127.0.0.1:9')
        monkeypatch.setattr(downloads, '_PREFIX', prefix)
    tag = 'vulscan-download-acceptance:' + uuid.uuid4().hex
    consumer = tag + '-run'
    repo = tmp_path / 'repo'
    repo.mkdir()
    if language == 'python':
        (repo/'requirements.txt').write_text('idna==3.10\n')
        (repo/'.python-version').write_text('3.11\n')
        run_command = ['python','-c','import idna; assert idna.__version__ == "3.10"; print("PYTHON_OK")']
    elif language == 'node':
        (repo/'package.json').write_text(json.dumps({'name':'download-acceptance','version':'1.0.0',
                    'engines':{'node':'24'},'dependencies':{'is-number':'7.0.0'}}))
        run_command = ['node','-e','if(!require("is-number")(42))process.exit(1);console.log("NODE_OK")']
    elif language == 'go':
        (repo/'go.mod').write_text('module download-acceptance\ngo 1.26\nrequire rsc.io/quote v1.5.2\n')
        run_command = ['./probe']
    else:
        run_command = ['sh','-c','/probe-c && /probe-cpp']
    try:
        if language == 'c':
            toolchain = replace(native_toolchain('c'), image=tag)
            ensure_toolchain(toolchain,run,proxy=proxy,timeout=300)
            before = len(calls)
            ensure_toolchain(toolchain,run,proxy='http://127.0.0.1:9',timeout=30)
        else:
            available = images.available_images(run)
            plan = replace(plan_for_repository(language,str(repo),available),tag=tag)
            assert ensure_dependency_image(plan,str(repo),run,proxy=proxy,build_timeout=300) == tag
            before = len(calls)
            assert ensure_dependency_image(plan,str(repo),run,proxy='http://127.0.0.1:9',build_timeout=30) == tag
        assert len(calls) == before + 1 and calls[-1][:3] == ['docker','image','inspect']
        builds = [argv for argv in calls[:before] if argv[:2] == ['docker','build']]
        assert len(builds) == (2 if fail_domestic else 1), '\n'.join(output)
        assert ('VULSCAN_DOWNLOAD_SOURCE=official' in builds[-1]) == fail_domestic
        assert all('HTTP_PROXY=' in argv for argv in builds[:1])
        # Real compilation and isolated runtime: no proxy or host networking.
        work = tmp_path / 'consumer'
        work.mkdir()
        recipe = f'FROM {tag}\n'
        if language == 'go':
            (work/'main.go').write_text('package main\nimport ("fmt"; "rsc.io/quote")\nfunc main(){fmt.Println(quote.Hello())}\n')
            (work/'go.mod').write_text((repo/'go.mod').read_text())
            recipe += 'COPY main.go go.mod /src/\nRUN GOPROXY=off go mod tidy && GOPROXY=off go build -o /src/probe .\n'
        if language == 'c':
            (work/'main.c').write_text('#include <stdio.h>\nint main(){puts("C_OK");}\n')
            (work/'main.cc').write_text('#include <iostream>\nint main(){std::cout<<"CPP_OK"<<std::endl;}\n')
            recipe += 'COPY main.c main.cc /test/\nRUN gcc /test/main.c -o /probe-c && g++ /test/main.cc -o /probe-cpp\n'
        recipe += 'CMD '+json.dumps(run_command)+'\n'
        (work/'Dockerfile').write_text(recipe)
        checked(['docker','build','--builder','default','-t',consumer,'.'],timeout=120,cwd=str(work))
        config = json.loads(checked(['docker','image','inspect','--format','{{json .Config.Env}}',consumer],timeout=30))
        assert not any(item.split('=',1)[0].upper().endswith('_PROXY') for item in config)
        checked(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                 '--memory','256m','--cpus','1','--pids-limit','128',consumer],timeout=30)
    finally:
        for owned in (consumer,tag):
            _run_command(['docker','image','rm',owned],timeout=30)


def test_real_mirror_image_and_cache(monkeypatch):
    # Deliberately uncached small official version; no global prune or removal of
    # a user's base. Shared result is retained for subsequent scans.
    ref = 'busybox:1.36.1-musl'
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        return _run_command(argv,**kw)
    def forbidden(*args, **kw):
        pytest.fail('国内镜像源成功时不应调用官方代理下载')
    monkeypatch.setattr(images,'pull_via_proxy',forbidden)
    result = images.ensure_base_images([ref],run,timeout=120,proxy='http://127.0.0.1:9')
    assert result.pulled == (ref,) or result.cached == (ref,)
    before = len(calls)
    assert images.ensure_base_images([ref],run,proxy='http://127.0.0.1:9').cached == (ref,)
    assert len(calls) == before+1


def test_real_mirror_failure_then_official_proxy(monkeypatch):
    proxy = os.environ.get('VULSCAN_TEST_PROXY')
    assert proxy
    # An actual failed docker pull against a refused local registry, followed by
    # real Docker Hub token/manifest/layer requests through Mihomo and docker load.
    monkeypatch.setattr(images,'_MIRROR','127.0.0.1:9')
    ref = 'busybox:1.37.0-musl'
    outcome = images.ensure_base_images([ref],_run_command,timeout=120,proxy=proxy)
    assert outcome.pulled == (ref,) or outcome.cached == (ref,)
    assert checked(['docker','run','--rm','--network','none',ref,'echo','PROXY_PULL_OK'],timeout=30) == 'PROXY_PULL_OK'


@pytest.mark.parametrize('fail_domestic', [False,True], ids=['domestic','proxy-takeover'])
def test_real_apk_download(tmp_path,monkeypatch,fail_domestic):
    proxy=os.environ.get('VULSCAN_TEST_PROXY')
    assert proxy
    if fail_domestic:
        monkeypatch.setattr(downloads,'_PREFIX',downloads._PREFIX.replace('mirrors.aliyun.com','127.0.0.1:9'))
    tag='vulscan-download-apk:'+uuid.uuid4().hex
    (tmp_path/'Dockerfile').write_text(downloads.render_downloads(
        'FROM golang:1.26-alpine\nRUN apk add --no-cache jq\nCMD ["jq","-n","true"]\n'))
    calls=[]
    def run(argv,**kw):
        calls.append(argv)
        return _run_command(argv,**kw)
    try:
        result=downloads.build_with_downloads(['docker','build','--builder','default','-t',tag,'.'],
                                               run,proxy=proxy,timeout=120,cwd=str(tmp_path))
        assert result[2]==0 and not result[3], '\n'.join(result[:2])
        builds=[argv for argv in calls if argv[:2]==['docker','build']]
        assert len(builds)==(2 if fail_domestic else 1)
        assert ('VULSCAN_DOWNLOAD_SOURCE=official' in builds[-1])==fail_domestic
        assert checked(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',tag],timeout=30)=='true'
    finally:
        _run_command(['docker','image','rm',tag],timeout=30)


def test_real_nonroot_build_preserves_shell_behavior(tmp_path):
    tag='vulscan-download-nonroot:'+uuid.uuid4().hex
    (tmp_path/'Dockerfile').write_text(downloads.render_downloads(
        'FROM node:24-slim\nUSER node\nSHELL ["/bin/sh","-e","-c"]\nRUN node --version\nCMD ["node","--version"]\n'))
    try:
        result=downloads.build_with_downloads(['docker','build','--builder','default','-t',tag,'.'],
                    _run_command,proxy='http://127.0.0.1:9',timeout=90,cwd=str(tmp_path))
        assert result[2]==0 and not result[3], '\n'.join(result[:2])
        assert 'Permission denied' not in '\n'.join(result[:2])
        assert checked(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',tag],timeout=30).startswith('v24.')
    finally:
        _run_command(['docker','image','rm',tag],timeout=30)
