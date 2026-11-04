"""国内下载源、一次代理接管、缓存与编译错误边界。"""
from contextlib import contextmanager

import pytest

from utilities.docker_build import downloads, images
from utilities.docker_build.errors import DockerBuildEnvironmentError
from utilities.docker_build.registry import image_reference


@pytest.mark.parametrize('ref,expected', [
    ('python:3.11-slim', ('docker.io', 'library/python', '3.11-slim')),
    ('org/app:1.2', ('docker.io', 'org/app', '1.2')),
    ('docker.io/python:3.12', ('docker.io', 'library/python', '3.12')),
    ('ghcr.io/org/app@sha256:abc', ('ghcr.io', 'org/app', 'sha256:abc')),
    ('registry.example:5000/org/app:1', ('registry.example:5000', 'org/app', '1')),
])
def test_image_versions_and_registry_are_preserved(ref, expected):
    assert image_reference(ref) == expected


def test_mirror_success_never_uses_proxy(monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        pytest.fail('国内源成功，不应触碰任务代理')
    monkeypatch.setattr(images, 'pull_via_proxy', forbidden)
    def runner(argv, **kw):
        calls.append(argv)
        if argv[1] == 'image':
            return '', 'missing', 1, False
        return 'done', '', 0, False
    result = images.ensure_base_images(['python:3.11-slim'], runner, proxy='http://127.0.0.1:9')
    assert result.pulled == ('python:3.11-slim',)
    assert calls[-1] == ['docker', 'tag', 'm.daocloud.io/docker.io/library/python:3.11-slim', 'python:3.11-slim']
    assert sum(argv[1] == 'pull' for argv in calls) == 1


def test_mirror_failure_uses_exact_official_version_once(monkeypatch):
    calls = []
    proxy_calls = []
    def pull(ref, proxy, runner, timeout):
        proxy_calls.append((ref, proxy, timeout))
        return ref
    monkeypatch.setattr(images, 'pull_via_proxy', pull)
    def runner(argv, **kw):
        calls.append(argv)
        return '', '404 Not Found', 1, False
    result = images.ensure_base_images(['node:24-slim'], runner, timeout=45, proxy='http://127.0.0.1:7890')
    assert result.pulled == ('node:24-slim',)
    assert len(proxy_calls) == 1 and proxy_calls[0][:2] == ('node:24-slim', 'http://127.0.0.1:7890')
    assert 0 < proxy_calls[0][2] <= 45
    assert all(argv[1] != 'pull' or argv[-1].startswith('m.daocloud.io/') for argv in calls)


def test_proxy_failure_has_no_third_source(monkeypatch):
    called = []
    def pull(*args):
        called.append(args)
        raise DockerBuildEnvironmentError('official connection timed out')
    monkeypatch.setattr(images, 'pull_via_proxy', pull)
    with pytest.raises(DockerBuildEnvironmentError, match='timed out'):
        images.ensure_base_images(['python:3.11-slim'], lambda *a, **kw: ('', '403 Forbidden', 1, False), proxy='http://127.0.0.1:9')
    assert len(called) == 1


def test_cache_hit_does_not_probe_any_source(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('不应进行网络下载')
    monkeypatch.setattr(images, 'pull_via_proxy', forbidden)
    calls = []
    def runner(argv, **kw):
        calls.append(argv)
        assert argv[:3] == ['docker', 'image', 'inspect']
        return 'sha256:cached', '', 0, False
    result = images.ensure_base_images(['golang:1.26-alpine'], runner, proxy='http://127.0.0.1:9')
    assert result.cached == ('golang:1.26-alpine',) and len(calls) == 1


def test_render_preserves_multistage_flags_exec_and_heredoc_data():
    text = '''FROM python:3.11-slim AS build
RUN --mount=type=cache,target=/root/.cache/pip python -m pip install idna==3.10
COPY <<EOF /tmp/data
RUN this is data
EOF
RUN ["python", "-c", "print('中文')"]
FROM build AS final
RUN <<'EOF'
printf '%s\\n' ok
EOF
CMD ["python"]
'''
    rendered = downloads.render_downloads(text)
    assert rendered.count('ARG VULSCAN_DOWNLOAD_SOURCE=domestic') == 2
    assert 'COPY <<EOF /tmp/data\nRUN this is data\nEOF' in rendered
    assert 'RUN --mount=type=cache,target=/root/.cache/pip export ' in rendered
    assert "python -c 'print('" in rendered
    assert 'RUN <<\'EOF\'\nexport PIP' in rendered
    assert 'CMD ["python"]' in rendered
    assert downloads.render_downloads(rendered) == rendered
    assert 'ENV HTTP_PROXY' not in rendered and 'ENV HTTPS_PROXY' not in rendered


def test_compose_prepares_only_actual_dockerfiles(tmp_path):
    (tmp_path / 'app').mkdir()
    (tmp_path / 'repository').mkdir()
    for name in ('app/Dockerfile', 'repository/Dockerfile'):
        (tmp_path / name).write_text('FROM python:3.11-slim\nRUN true\n')
    (tmp_path / 'docker-compose.yml').write_text('services:\n  app:\n    build: app\n')
    downloads.prepare_downloads(str(tmp_path), compose=True)
    assert 'VULSCAN_DOWNLOAD_SOURCE' in (tmp_path / 'app/Dockerfile').read_text()
    assert 'VULSCAN_DOWNLOAD_SOURCE' not in (tmp_path / 'repository/Dockerfile').read_text()


@pytest.mark.parametrize('error', [
    'ERROR: No matching distribution found for a==1.0',
    'npm error code ETARGET', 'go: dial tcp: i/o timeout',
    'E: Failed to fetch https://mirror/x 404 Not Found',
    'WARNING: fetching https://mirror/apk: temporary error (try again later)',
])
def test_download_failure_classifier(error):
    assert downloads.is_download_failure(error)


@pytest.mark.parametrize('error', [
    'gcc: error: expected declaration', 'undefined: err', 'timeout.c: error: expected declaration',
    'npm error code EINTEGRITY\n404 Not Found', 'checksum mismatch\ni/o timeout',
    'no space left on device\nconnection reset',
    'process "/bin/sh -c ' + downloads._PREFIX + 'gcc test.c" did not complete successfully',
])
def test_compiler_integrity_and_host_errors_never_trigger_source_switch(error):
    assert not downloads.is_download_failure(error)


def test_one_official_retry_shares_budget_and_keeps_proxy_out_of_first_attempt(monkeypatch):
    calls = []
    @contextmanager
    def proxy(value, runner):
        assert value == 'http://127.0.0.1:7890'
        yield ['--build-arg', 'HTTP_PROXY=http://172.17.0.1:39901']
    monkeypatch.setattr(downloads, 'build_proxy_arguments', proxy)
    def runner(argv, **kw):
        calls.append((argv, kw))
        if len(calls) == 1:
            return '', 'No matching distribution found for x==1', 1, False
        return 'success', '', 0, False
    outcome = downloads.build_with_downloads(['docker', 'build', '.'], runner, proxy='http://127.0.0.1:7890', timeout=100)
    assert outcome[2] == 0 and len(calls) == 2
    assert 'HTTP_PROXY=' in calls[0][0] and 'VULSCAN_DOWNLOAD_SOURCE=domestic' in calls[0][0]
    assert 'HTTP_PROXY=http://172.17.0.1:39901' in calls[1][0] and 'VULSCAN_DOWNLOAD_SOURCE=official' in calls[1][0]
    assert 0 < calls[1][1]['timeout'] <= calls[0][1]['timeout'] == 100


def test_compile_error_and_domestic_success_do_not_even_probe_broken_proxy(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('不应访问备用代理')
    monkeypatch.setattr(downloads, 'build_proxy_arguments', forbidden)
    for outcome in (('ok', '', 0, False), ('', 'gcc: error: syntax', 1, False)):
        calls = []
        def runner(argv, **kw):
            calls.append(argv)
            return outcome
        assert downloads.build_with_downloads(['docker','build','.'], runner, proxy='http://127.0.0.1:9') == outcome
        assert len(calls) == 1


def test_digest_replacement_only_touches_bases(tmp_path):
    ref = 'python@sha256:' + 'a'*64
    text = f'FROM {ref} AS build\nRUN echo {ref}\nFROM build\n'
    (tmp_path / 'Dockerfile').write_text(text)
    images.replace_base_references(str(tmp_path), [(ref, 'vulscan/base-cache:aaa')])
    assert (tmp_path / 'Dockerfile').read_text() == text.replace('FROM '+ref, 'FROM vulscan/base-cache:aaa')


def test_renderer_handles_multiline_json_and_quoted_heredoc_text():
    text = 'FROM python:3.11-slim\nRUN ["python", \\\n"-c", "print(42)"]\nRUN echo "<<EOF"\nRUN python -m pip --version\n'
    rendered = downloads.render_downloads(text)
    assert "python -c 'print(42)'" in rendered
    assert rendered.count('export PIP_DEFAULT_TIMEOUT=15') == 3
    assert 'echo "<<EOF"' in rendered


def test_digest_arg_default_is_replaced_with_verified_local_cache(tmp_path):
    ref = 'python@sha256:'+'a'*64
    (tmp_path/'Dockerfile').write_text(f'ARG BASE={ref}\nFROM ${{BASE}} AS build\nFROM build\n')
    assert images.dockerfile_bases(str(tmp_path)) == (ref,)
    images.replace_base_references(str(tmp_path),[(ref,'vulscan/base-cache:aaa')])
    assert f'ARG BASE={ref}' in (tmp_path/'Dockerfile').read_text()
    assert 'FROM vulscan/base-cache:aaa AS build' in (tmp_path/'Dockerfile').read_text()


def test_distribution_mirrors_preserve_transport_and_verification():
    setup = downloads._SETUP
    for insecure in ('Verify-Peer', '--trusted-host', '--allow-unauthenticated', 'GOSUMDB=off', '--allow-untrusted'):
        assert insecure not in setup


def test_download_error_summary_keeps_real_reason_and_omits_setup():
    text = '#5 RUN ' + downloads._PREFIX + 'apt-get update\nE: Failed to fetch mirror: certificate verification failed\nprocess "' + downloads._PREFIX + 'apt-get update" failed'
    detail = downloads.download_diagnostic(text)
    assert detail == 'E: Failed to fetch mirror: certificate verification failed'
    assert downloads.is_download_failure(text)


def test_final_stage_without_newline_stays_valid():
    text='FROM python:3.11-slim\nRUN true\nFROM scratch'
    assert 'FROM scratch\nARG ' in downloads.render_downloads(text)


def test_invalid_proxy_is_rejected_before_network_or_logging(capsys):
    def forbidden(*args, **kw):
        pytest.fail('无效代理不应产生任何 Docker 或网络调用')
    for call in (lambda: images.ensure_base_images(['python:3.11-slim'], forbidden, proxy='http://user:secret@127.0.0.1:7890'),
                 lambda: downloads.build_with_downloads(['docker','build','.'], forbidden, proxy='http://user:secret@127.0.0.1:7890')):
        with pytest.raises(ValueError,match='代理'):
            call()
    assert 'secret' not in capsys.readouterr().err
