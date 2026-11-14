"""Catalog, platform detection, command resolution and local state."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


class LazyError(Exception):
    pass


def state_dir():
    return Path(os.environ.get('LSCRIPT_STATE_DIR', str(Path.home() / '.local/share/lscript-updated')))


def load_catalog():
    path = Path(os.environ.get('LSCRIPT_CATALOG', str(PROJECT / 'data/catalog.json')))
    data = json.loads(path.read_text())
    seen = set()
    for record in data['records']:
        key = record['id']
        if key in seen or not re.fullmatch('[a-z0-9]+', key):
            raise LazyError(f'Duplicate/invalid catalog ID: {key}')
        seen.add(key)
    return data


def tool(value):
    key = re.sub('[^a-z0-9]', '', value.lower())
    for record in load_catalog()['records']:
        if key == record['id'] or value.lower() == record['name'].lower():
            return record
    raise LazyError(f'Unknown tool {value!r}. Use: lazy list --search TERM')


def distro(path=Path('/etc/os-release')):
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key, value = line.split('=', 1)
                values[key] = value.strip().strip('"')
    name = values.get('ID', 'unknown')
    family = set(values.get('ID_LIKE', '').split()) | {name}
    return dict(id=name, version=values.get('VERSION_ID','unknown'),
                supported=bool(family & {'kali','debian','ubuntu'}))


def run(argv, *, capture=False, cwd=None, timeout=None, env=None):
    try:
        result = subprocess.run([str(x) for x in argv], capture_output=capture, text=True,
                                cwd=cwd, timeout=timeout, env=env, check=False)
    except FileNotFoundError as exc:
        raise LazyError(f'Executable not found: {argv[0]}') from exc
    except subprocess.TimeoutExpired as exc:
        raise LazyError(f'Command timed out: {argv[0]}') from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or '').strip() if capture else ''
        raise LazyError(f'{argv[0]} failed (exit {result.returncode}). {detail}')
    return result.stdout.strip() if capture else ''


def launch_bindings(record):
    return [b for b in record.get('bindings', []) if b.get('kind') != 'reference' and not b.get('action')]


def resolve(record):
    # Prefer existing binaries and explicit legacy command variants; no reinstall.
    for binding in launch_bindings(record):
        path = shutil.which(binding['command'])
        if path:
            return [path], binding.get('kind', 'cli')
    for command in record.get('commands', []):
        path = shutil.which(command)
        if path:
            return [path], record.get('kind', 'cli')
    managed = state_dir() / 'tools' / record['id'] / 'installed.json'
    if managed.exists():
        data = json.loads(managed.read_text())
        argv = data.get('argv', [])
        if argv and Path(argv[0]).is_file():
            return argv, record.get('kind', 'cli')
    # Explicit source entry points only, never guess an arbitrary executable.
    for item in record.get('local_entries', []):
        base = Path(item['directory']).expanduser()
        entry = base / item['entry']
        if entry.is_file() and shutil.which(item['interpreter']):
            return [item['interpreter'], str(entry)], 'cli'
    return None, None


def status(record):
    argv, _ = resolve(record)
    if argv: return 'installed'
    if record.get('recipe'): return 'installable'
    if any(b.get('kind') == 'reference' and shutil.which(b['command']) for b in record.get('bindings', [])):
        return 'source-only'
    return 'review-needed'


def display_info(record):
    print(f"\n{record['name']} [{record['id']}] — {status(record)}")
    print(record.get('description', 'Imported tool; upstream compatibility review required.'))
    print('Categories: ' + ', '.join(record.get('categories', [])))
    argv, kind = resolve(record)
    if argv: print('Existing command: ' + shlex.join(argv) + f' ({kind})')
    if record.get('recipe'): print('Installation: ' + json.dumps(record['recipe']))
    for source in record.get('sources', []):
        print(f"  Source: {source['suite']} / {source['source_id']}: {source['label']}")
    for url in record.get('repositories', []): print('  Repository: ' + url)
    if status(record) == 'review-needed':
        print('Preserved catalog entry. No compatible installer/execution recipe has been added.')


def execute(record, arguments, *, action=None):
    argv, kind = resolve(record)
    if action:
        selected = record.get('actions', {}).get(action)
        if not selected: raise LazyError('Unknown action. Available: ' + ', '.join(record.get('actions', {})))
        command = shutil.which(selected)
        manifest = state_dir() / 'tools' / record['id'] / 'installed.json'
        if not command and manifest.exists():
            candidate = json.loads(manifest.read_text()).get('actions', {}).get(action)
            if candidate and Path(candidate).is_file(): command = candidate
        if not command and argv:
            possible = Path(argv[0]).parent / selected
            if possible.is_file(): command = str(possible)
        if not command: raise LazyError(f'Action executable not found: {selected}')
        argv = [command]
        if action == 'gui': kind = 'gui'
    if not argv:
        raise LazyError(f"{record['name']} is {status(record)}. See `lazy info {record['id']}`.")
    if kind == 'gui' and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        raise LazyError('This GUI tool needs a graphical desktop. Use a CLI alternative for this session.')
    if kind == 'root' and os.geteuid() != 0:
        argv = ['sudo', *argv]
    # Scripts with relative config/data files need their original working directory.
    cwd = None
    for item in record.get('local_entries', []):
        if len(argv) > 1 and argv[-1] == str(Path(item['directory']).expanduser() / item['entry']):
            cwd = Path(item['directory']).expanduser()
    run([*argv, *arguments], cwd=cwd)
