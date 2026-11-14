"""Explicit package/venv/verified-release installation; no upstream shell installers."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from .core import LazyError, distro, resolve, run, state_dir


def github_token():
    if os.environ.get('GITHUB_TOKEN'): return os.environ['GITHUB_TOKEN']
    credential_file = Path(os.environ.get('BCHACKTOOL_CREDENTIAL_FILE',
                           str(Path.home() / '.config/bchacktool/github.json')))
    if credential_file.exists(): return json.loads(credential_file.read_text()).get('token')
    return None


class StripAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirect = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirect is not None: redirect.remove_header('Authorization')
        return redirect


def download(url, *, api=False, maximum=1024*1024*1024):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https': raise LazyError('Downloads require HTTPS.')
    headers = {'User-Agent': 'MusicCityTelecom-lscript-updated/3'}
    token = github_token() if api and parsed.hostname == 'api.github.com' else None
    if token: headers['Authorization'] = f'Bearer {token}'
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.build_opener(StripAuthRedirect()).open(request, timeout=60) as response:
            content = response.read(maximum + 1)
        if len(content) > maximum: raise LazyError('Download exceeded the configured size limit.')
        return content
    except urllib.error.HTTPError as exc:
        if exc.code == 401 and token:
            print('GitHub token rejected; trying public access anonymously.')
            return download(url, api=False, maximum=maximum)
        raise LazyError(f'HTTP {exc.code}: repository/asset unavailable, access denied, or rate limited.') from exc
    except urllib.error.URLError as exc:
        raise LazyError(f'Network/DNS/TLS error: {exc.reason}') from exc


def package_available(package):
    if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package): raise LazyError('Invalid package name in recipe.')
    try:
        output = run(['apt-cache', 'policy', package], capture=True)
    except LazyError: return False
    candidate = re.search(r'Candidate:\s*(\S+)', output)
    return bool(candidate and candidate.group(1) != '(none)')


def install_apt(packages):
    if not distro()['supported']: raise LazyError('APT recipes require Kali, Debian or Ubuntu.')
    missing = [package for package in packages if not package_available(package)]
    if missing:
        raise LazyError('Unavailable packages in your configured repositories: ' + ', '.join(missing) +
                        '. Refresh apt metadata or use the upstream instructions. No foreign distro repository was added.')
    prefix = [] if os.geteuid() == 0 else ['sudo']
    run([*prefix, 'apt-get', 'install', '-y', '--', *packages])


def java_home(minimum):
    candidates = []
    javac = shutil.which('javac')
    if javac: candidates.append(Path(javac).resolve().parents[1])
    if Path('/usr/lib/jvm').exists(): candidates.extend(Path('/usr/lib/jvm').iterdir())
    for candidate in candidates:
        executable = candidate / 'bin/javac'
        if not executable.is_file(): continue
        result = subprocess.run([str(executable), '-version'], capture_output=True, text=True, timeout=10)
        match = re.search(r'javac\s+(\d+)', result.stdout + result.stderr)
        if match and int(match.group(1)) >= minimum: return candidate
    raise LazyError(f'JDK {minimum}+ is required. Install a supported JDK, then retry. '
                    f'If available on your distro: sudo apt install openjdk-{minimum}-jdk')


def safe_unzip(data, directory):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 60000 or sum(item.file_size for item in entries) > 4*1024**3:
            raise LazyError('Archive is too large to extract.')
        for item in entries:
            path = Path(item.filename)
            mode = item.external_attr >> 16
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or stat.S_ISLNK(mode):
                raise LazyError('Unsafe archive member; extraction cancelled.')
        for item in entries:
            target = directory / item.filename
            if item.is_dir(): target.mkdir(parents=True, exist_ok=True); continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
            permissions = (item.external_attr >> 16) & 0o777
            if permissions: target.chmod(permissions)


def release_install(record, recipe, *, sha256=None, asset_name=None):
    metadata = json.loads(download(f"https://api.github.com/repos/{recipe['repository']}/releases/latest", api=True, maximum=8*1024*1024))
    assets = [asset for asset in metadata['assets'] if re.fullmatch(recipe['asset_pattern'], asset['name'], re.I)]
    if asset_name: assets = [asset for asset in assets if asset['name'] == asset_name]
    if len(assets) != 1:
        raise LazyError('Release selection is ambiguous/unavailable. Use --asset NAME. Matches: ' +
                        ', '.join(asset['name'] for asset in assets))
    asset = assets[0]
    digest = sha256 or (asset.get('digest') or '').removeprefix('sha256:')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', digest or ''):
        raise LazyError('No SHA-256 supplied by GitHub for this asset. Verify the upstream checksum and pass --sha256 HASH.')
    content = download(asset['browser_download_url'])
    if hashlib.sha256(content).hexdigest().lower() != digest.lower():
        raise LazyError('SHA-256 mismatch; nothing installed.')
    parent = state_dir() / 'tools' / record['id']
    parent.mkdir(parents=True, exist_ok=True)
    version = re.sub(r'[^A-Za-z0-9_.-]', '_', metadata['tag_name'])
    destination = parent / version
    with tempfile.TemporaryDirectory(dir=parent) as temp:
        staging = Path(temp)
        if recipe.get('format') == 'appimage':
            if platform.machine().lower() not in ('x86_64','amd64'):
                raise LazyError('This AppImage recipe is for x86-64. Use a matching upstream build for your architecture.')
            executable = staging / 'Cutter.AppImage'
            executable.write_bytes(content)
            executable.chmod(0o755)
        else:
            safe_unzip(content, staging)
            matches = list(staging.glob(recipe['entry_glob']))
            if len(matches) != 1: raise LazyError('Expected release entry point not found uniquely.')
            executable = matches[0]
            executable.chmod(executable.stat().st_mode | 0o111)
        minimum = recipe.get('java_min')
        if record['id'] == 'ghidra':
            properties = list(staging.glob('*/Ghidra/application.properties'))
            if properties:
                match = re.search(r'^application.java.min=(\d+)', properties[0].read_text(), re.M)
                if match: minimum = int(match.group(1))
        java = java_home(minimum) if minimum else None
        relative = executable.relative_to(staging)
        if destination.exists():
            raise LazyError('This release directory already exists; review it before reinstalling.')
        shutil.move(str(staging), destination)
    executable = destination / relative
    launcher = parent / 'launch'
    lines = ['#!/bin/sh']
    if java: lines += ['export JAVA_HOME=' + shlex.quote(str(java))]
    lines += ['exec ' + shlex.quote(str(executable)) + ' "$@"']
    launcher.write_text('\n'.join(lines)+'\n'); launcher.chmod(0o755)
    manifest = dict(argv=[str(launcher)], version=metadata['tag_name'], sha256=digest)
    manifest['actions'] = {}
    for name, command in record.get('actions', {}).items():
        candidate = executable.parent / command
        if candidate.is_file():
            candidate.chmod(candidate.stat().st_mode | 0o111)
            action_launcher = parent / ('launch-' + name)
            action_lines = ['#!/bin/sh']
            if java: action_lines.append('export JAVA_HOME=' + shlex.quote(str(java)))
            action_lines.append('exec ' + shlex.quote(str(candidate)) + ' "$@"')
            action_launcher.write_text('\n'.join(action_lines)+'\n'); action_launcher.chmod(0o755)
            manifest['actions'][name] = str(action_launcher)
    (parent / 'installed.json').write_text(json.dumps(manifest, indent=2))


def plan(record):
    argv, _ = resolve(record)
    if argv: return f"{record['name']}: reuse {shlex.join(argv)}"
    recipe = record.get('recipe')
    if not recipe: return f"{record['name']}: review-needed; no automated recipe"
    return f"{record['name']}: {json.dumps(recipe, sort_keys=True)}"


def install(record, *, dry_run=False, sha256=None, asset_name=None):
    print(plan(record))
    if dry_run or resolve(record)[0]: return
    recipe = record.get('recipe')
    if not recipe: raise LazyError('No installation recipe for this preserved entry.')
    if recipe['kind'] == 'apt': install_apt(recipe['packages'])
    elif recipe['kind'] == 'pip':
        base = state_dir() / 'tools' / record['id']
        python = base / 'venv/bin/python'
        if not python.exists():
            run([sys_executable(), '-m', 'venv', str(base / 'venv')])
        run([python, '-m', 'pip', 'install', recipe['package']])
        entry = base / 'venv/bin' / recipe['entry']
        if not entry.is_file(): raise LazyError('Installed package did not provide the expected command.')
        (base / 'installed.json').write_text(json.dumps(dict(argv=[str(entry)])))
    elif recipe['kind'] == 'release': release_install(record, recipe, sha256=sha256, asset_name=asset_name)
    else: raise LazyError('Unsupported recipe kind.')
    if not resolve(record)[0]:
        raise LazyError('Installation command completed, but the expected executable was not found. Run lazy doctor.')


def sys_executable():
    import sys
    return sys.executable
