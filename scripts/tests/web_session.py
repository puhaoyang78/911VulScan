#!/usr/bin/env python3
"""Authenticate deployment acceptance; never bypass the application's accounts."""
import argparse
import http.cookiejar
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def client(base, home, initialize=False):
    cookies = home / '.vulscan/deployment-acceptance.cookies'
    jar = http.cookiejar.LWPCookieJar(str(cookies))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    if initialize:
        page = opener.open(base + '/setup', timeout=10).read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        token = (home / '.vulscan/webui/.access/bootstrap-token').read_text().strip()
        form = {'username': 'deployment-admin', 'password': secrets.token_urlsafe(32), 'bootstrap': token, 'csrf': csrf}
        with opener.open(base + '/setup', urllib.parse.urlencode(form).encode(), timeout=10) as response:
            assert response.status == 200
        jar.save(ignore_discard=True)
        cookies.chmod(0o600)
    else:
        jar.load(ignore_discard=True)
    with opener.open(base + '/account', timeout=10) as response:
        assert json.load(response)['username'] == 'deployment-admin'
    return opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--initialize', action='store_true')
    parser.add_argument('--expect-history')
    args = parser.parse_args()
    opener = client(args.url, args.home, args.initialize)
    with opener.open(args.url + '/', timeout=10) as response:
        page = response.read().decode()
        assert response.status == 200 and 'stat-total' in page
        if args.expect_history:
            assert args.expect_history in page, 'Authenticated history was not restored'
    anonymous = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        anonymous.open(args.url + '/', timeout=10)
    except urllib.error.HTTPError as error:
        assert error.code == 401
    else:
        raise AssertionError('Anonymous requests can read private history')
    print('Deployment administrator session, private history and anonymous denial: PASS')


if __name__ == '__main__':
    main()
