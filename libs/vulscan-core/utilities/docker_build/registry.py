"""通过任务代理获取公开 Registry v2 镜像，并校验后导入本机 Docker。"""

import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

import requests

from utilities.docker_build.errors import DockerBuildEnvironmentError

_ACCEPT = ', '.join((
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
))


def image_reference(ref: str) -> tuple[str, str, str]:
    """规范化注册表、仓库与标签/摘要，保留原始版本。"""
    if '@' in ref:
        name, version = ref.rsplit('@', 1)
    elif ':' in ref.rsplit('/', 1)[-1]:
        name, version = ref.rsplit(':', 1)
    else:
        name, version = ref, 'latest'
    first, separator, rest = name.partition('/')
    if separator and ('.' in first or ':' in first or first == 'localhost'):
        registry, repository = first, rest
    else:
        registry, repository = 'docker.io', name
    if registry == 'm.daocloud.io':
        registry, _, repository = repository.partition('/')
    elif registry == 'docker.m.daocloud.io':
        registry = 'docker.io'
    if registry in ('index.docker.io', 'registry-1.docker.io'):
        registry = 'docker.io'
    if registry == 'docker.io' and '/' not in repository:
        repository = 'library/' + repository
    return registry, repository, version


def _checked_digest(data: bytes, digest: str) -> None:
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest or ''):
        raise DockerBuildEnvironmentError('镜像使用不支持或无效的摘要：' + str(digest))
    if 'sha256:' + hashlib.sha256(data).hexdigest() != digest:
        raise DockerBuildEnvironmentError('镜像内容摘要校验失败：' + digest)


def pull_via_proxy(ref: str, proxy: str, runner, timeout: float) -> str:
    """不改变 daemon 配置。返回可供 FROM 使用的引用（摘要引用使用已校验的本地标签）。"""
    registry, repository, version = image_reference(ref)
    host = 'registry-1.docker.io' if registry == 'docker.io' else registry
    deadline = time.monotonic() + timeout
    session = requests.Session()
    session.trust_env = False
    session.headers["Accept-Encoding"] = "identity"
    session.proxies = {'http': proxy, 'https': proxy}
    token = None

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('官方镜像代理下载总预算已耗尽')
        return left

    def get(url, *, stream=False):
        nonlocal token
        headers = {'Accept': _ACCEPT}
        if token and urlsplit(url).hostname == host:
            headers['Authorization'] = 'Bearer ' + token
        response = session.get(url, headers=headers, timeout=(min(15, remaining()), min(30, remaining())), stream=stream)
        if response.status_code == 401 and not token:
            challenge = response.headers.get('WWW-Authenticate', '')
            response.close()
            fields = dict(re.findall(r'(\w+)="([^"]+)"', challenge))
            realm = fields.pop('realm', '')
            if not challenge.lower().startswith('bearer ') or urlsplit(realm).scheme != 'https':
                raise DockerBuildEnvironmentError('官方镜像需要登录或不支持的认证：' + registry)
            # 只使用公开 pull token，绝不读取或转发服务账号的 Docker/API 凭据。
            with session.get(realm, params=fields, timeout=(min(15, remaining()), min(30, remaining()))) as auth:
                auth.raise_for_status()
                payload = auth.json()
                token = payload.get('token') or payload.get('access_token')
            if not token:
                raise DockerBuildEnvironmentError('镜像注册表未返回公开拉取令牌')
            return get(url, stream=stream)
        try:
            response.raise_for_status()
        except requests.RequestException:
            response.close()
            raise
        return response

    def manifest(reference):
        with get(f'https://{host}/v2/{repository}/manifests/{reference}') as response:
            data = response.content
            if len(data) > 4 * 1024 * 1024:
                raise DockerBuildEnvironmentError('镜像清单超出大小限制')
            digest = reference if reference.startswith('sha256:') else response.headers.get('Docker-Content-Digest')
            if digest:
                _checked_digest(data, digest)
            return json.loads(data), 'sha256:' + hashlib.sha256(data).hexdigest()

    try:
        with tempfile.TemporaryDirectory(prefix='vulscan-pull-') as tmp:
            root = Path(tmp)
            metadata, manifest_digest = manifest(version)
            if 'manifests' in metadata:
                out, err, code, timed = runner(['docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}'], timeout=min(30, remaining()))
                if code or timed:
                    raise DockerBuildEnvironmentError('无法确定 Docker 目标平台：' + (err or out))
                operating_system, arch = out.strip().split('/', 1)
                arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'arm'}.get(arch, arch)
                candidates = [item for item in metadata['manifests']
                              if item.get('platform', {}).get('os') == operating_system
                              and item.get('platform', {}).get('architecture') == arch]
                if not candidates:
                    raise DockerBuildEnvironmentError(f'镜像 {ref} 没有 {operating_system}/{arch} 版本')
                metadata, _ = manifest(candidates[0]['digest'])
            config = metadata['config']
            target = ref if '@' not in ref else 'vulscan/base-cache:' + manifest_digest.split(':')[1]
            out, _err, code, timed = runner(['docker', 'image', 'inspect', '--format', '{{.Id}}', config['digest']], timeout=min(30, remaining()))
            if not code and not timed and out.strip() == config['digest']:
                out, err, code, timed = runner(['docker', 'tag', config['digest'], target], timeout=min(30, remaining()))
                if code or timed:
                    raise DockerBuildEnvironmentError('复用已缓存镜像失败：' + (err or out))
                return target
            descriptors = [config, *metadata['layers']]
            names = []
            for descriptor in descriptors:
                digest = descriptor['digest']
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                    raise DockerBuildEnvironmentError('镜像层摘要无效：' + digest)
                filename = digest.split(':')[1]
                path = root / filename
                size = 0
                checksum = hashlib.sha256()
                with get(f'https://{host}/v2/{repository}/blobs/{digest}', stream=True) as response, path.open('wb') as output:
                    for chunk in response.iter_content(1024 * 1024):
                        remaining()
                        size += len(chunk)
                        checksum.update(chunk)
                        output.write(chunk)
                if size != descriptor['size'] or 'sha256:' + checksum.hexdigest() != digest:
                    raise DockerBuildEnvironmentError('镜像层大小或摘要校验失败：' + digest)
                names.append(filename)
            # Docker archive 接受压缩层；daemon 在 load 时继续验证 rootfs diff_ids。
            # 摘要引用不能通过 docker tag 创建，改用绑定已验证清单摘要的本地标签。
            archive = root / 'image.tar'
            with tarfile.open(archive, 'w') as bundle:
                for filename in names:
                    bundle.add(root / filename, arcname=filename)
                data = json.dumps([{'Config': names[0], 'RepoTags': [target], 'Layers': names[1:]}]).encode()
                entry = tarfile.TarInfo('manifest.json')
                entry.size = len(data)
                bundle.addfile(entry, io.BytesIO(data))
            out, err, code, timed = runner(['docker', 'load', '--input', str(archive)], timeout=remaining())
            if code or timed:
                raise DockerBuildEnvironmentError('代理镜像导入失败：' + (err or out)[-2000:])
            return target
    except (requests.RequestException, OSError, ValueError, KeyError, TypeError) as exc:
        raise DockerBuildEnvironmentError(f'官方镜像 {ref} 通过代理下载失败：{exc}') from exc
    finally:
        session.close()
