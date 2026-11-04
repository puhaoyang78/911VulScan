"""代理拉取保留版本、平台与 SHA-256；错误内容绝不导入 daemon。"""
import hashlib
import json
import tarfile

import pytest
import requests

from utilities.docker_build import registry
from utilities.docker_build.errors import DockerBuildEnvironmentError


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def descriptor(data):
    return {'digest': 'sha256:' + hashlib.sha256(data).hexdigest(), 'size': len(data)}


def response(url, data, status=200, **headers):
    item = requests.Response()
    item.status_code = status
    item.url = url
    item._content = data
    item._content_consumed = True
    item.headers.update(headers)
    return item


@pytest.fixture
def registry_fixture(monkeypatch):
    layer = b'controlled compressed image layer'
    config = encoded({'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[]}})
    document = encoded({'schemaVersion':2,'config':descriptor(config),'layers':[descriptor(layer)]})
    manifest_digest = descriptor(document)['digest']
    index = encoded({'schemaVersion':2,'manifests':[
        {'digest':manifest_digest,'platform':{'os':'linux','architecture':'amd64'}},
        {'digest':'sha256:'+'e'*64,'platform':{'os':'linux','architecture':'arm64'}},
    ]})
    data = {'index':index,'manifest':document,'config':config,'layer':layer,
            'requests':[],'commands':[],'loaded':None,'authenticated':False}
    class Session:
        def __init__(self):
            self.headers = {}
        def close(self):
            data['closed'] = True
        def get(self, url, **kw):
            data['requests'].append((url, kw))
            assert self.trust_env is False
            assert self.proxies == {'http':'http://127.0.0.1:7890','https':'http://127.0.0.1:7890'}
            if 'auth.docker.io' in url:
                data['authenticated'] = True
                return response(url, encoded({'token':'fixture-token'}))
            if not data['authenticated']:
                return response(url,b'',401, **{'WWW-Authenticate':'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:pull"'})
            assert kw['headers'].get('Authorization') == 'Bearer fixture-token'
            if '/manifests/' in url:
                body = data['index'] if url.endswith('/3.11-slim') else data['manifest']
                return response(url,body,**{'Docker-Content-Digest':descriptor(body)['digest']})
            if url.endswith(descriptor(config)['digest']):
                return response(url,data['config'])
            if url.endswith(descriptor(layer)['digest']):
                return response(url,data['layer'])
            pytest.fail('Unexpected URL: '+url)
    monkeypatch.setattr(registry.requests, 'Session', Session)
    def runner(argv, **kw):
        data['commands'].append(argv)
        assert kw['timeout'] > 0
        if argv[1] == 'info':
            return 'linux/x86_64', '', 0, False
        if argv[1] == 'image':
            return '', 'missing', 1, False
        if argv[1] == 'load':
            with tarfile.open(argv[-1]) as bundle:
                manifest = json.load(bundle.extractfile('manifest.json'))[0]
                data['loaded'] = (manifest, {name:bundle.extractfile(name).read() for name in [manifest['Config'],*manifest['Layers']]})
            return 'loaded', '', 0, False
        pytest.fail('Unexpected command: '+repr(argv))
    data['runner'] = runner
    return data


def test_official_pull_auth_platform_and_archive(registry_fixture):
    data = registry_fixture
    result = registry.pull_via_proxy('python:3.11-slim','http://127.0.0.1:7890',data['runner'],30)
    assert result == 'python:3.11-slim'
    manifest, blobs = data['loaded']
    assert manifest['RepoTags'] == ['python:3.11-slim']
    assert blobs[manifest['Config']] == data['config']
    assert blobs[manifest['Layers'][0]] == data['layer']
    assert len([url for url, _ in data['requests'] if 'auth.docker.io' in url]) == 1
    assert all('m.daocloud' not in url for url, _ in data['requests'])
    assert data['closed']


@pytest.mark.parametrize('corrupt', ['config','layer','manifest'])
def test_corrupt_content_is_never_loaded(registry_fixture, corrupt):
    data = registry_fixture
    data[corrupt] += b'corrupt'
    with pytest.raises(DockerBuildEnvironmentError,match='校验失败'):
        registry.pull_via_proxy('python:3.11-slim','http://127.0.0.1:7890',data['runner'],30)
    assert data['loaded'] is None
    assert data['closed']


def test_pinned_manifest_uses_verified_local_reference(registry_fixture):
    data = registry_fixture
    digest = descriptor(data['manifest'])['digest']
    result = registry.pull_via_proxy('python@'+digest,'http://127.0.0.1:7890',data['runner'],30)
    assert result == 'vulscan/base-cache:' + digest.split(':')[1]
    assert data['loaded'][0]['RepoTags'] == [result]
    assert all('latest' not in url for url,_ in data['requests'])


def test_cached_config_reuses_image_without_downloading_layers(registry_fixture):
    data = registry_fixture
    checksum = descriptor(data['config'])['digest']
    def cached(argv, **kw):
        if argv[1] == 'image':
            assert argv[-1] == checksum
            return checksum, '', 0, False
        if argv[1] == 'tag':
            assert argv[-2:] == [checksum, 'python:3.11-slim']
            return '', '', 0, False
        return data['runner'](argv,**kw)
    assert registry.pull_via_proxy('python:3.11-slim','http://127.0.0.1:7890',cached,30) == 'python:3.11-slim'
    assert all('/blobs/' not in url for url,_ in data['requests'])
    assert data['loaded'] is None
