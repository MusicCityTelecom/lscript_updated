"""User-level installation plus backed-up integration into pentest-menu."""
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import shutil
import tempfile
from .core import LazyError, PROJECT, load_catalog, run
from .pentest_patch import patch_menu


def user_bin(): return Path.home()/'.local/bin'


def self_install():
    if os.geteuid() == 0:
        raise LazyError('Run install.sh as your normal desktop user. Individual package installs use sudo when needed.')
    directory=user_bin(); directory.mkdir(parents=True,exist_ok=True)
    for name in ['lazy','l','lscript']:
        path=directory/name
        if path.exists() or path.is_symlink():
            if path.is_symlink() and path.resolve() == PROJECT/'l': continue
            print(f'Preserved existing command: {path}; no overwrite performed.')
            continue
        path.symlink_to(PROJECT/'l')
        print(f'Installed {path}')
    if str(directory) not in os.environ.get('PATH','').split(os.pathsep):
        print('Add this to your shell configuration: export PATH="$HOME/.local/bin:$PATH"')


def self_uninstall():
    for name in ['lazy','l','lscript']:
        path=user_bin()/name
        if path.is_symlink() and path.resolve() == PROJECT/'l':
            path.unlink(); print(f'Removed managed launcher {path}')
    print('Tool installations, source archives and user data were preserved.')


def write_executable(path, content):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(content); path.chmod(0o755)


def install_system_file(source, destination):
    if os.access(destination, os.W_OK):
        temporary=destination.with_name(destination.name+'.lscript-new')
        shutil.copy2(source,temporary); temporary.chmod(0o755); temporary.replace(destination)
    else:
        run(['sudo','install','-m','0755',str(source),str(destination)])


def integrate(menu, *, apply=False, preview=None):
    menu=Path(menu).expanduser().resolve()
    if not menu.is_file(): raise LazyError('Existing pentest-menu was not found.')
    original=menu.read_text(); patched=patch_menu(original)
    if preview:
        Path(preview).write_text(patched)
        print(f'Integration preview saved: {preview}')
    print(f'Target: {menu}; {len(load_catalog()["records"])} deduplicated catalog entries')
    print('Original tool directories and LScript/BCHackTool files will not be modified.')
    if not apply:
        print('Preview only. Apply with: lazy integrate --apply')
        return
    runtime=Path.home()/'.local/share/pentest-menu-integration'
    config=Path.home()/'.config/pentest-menu/tools.list'
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup=Path.home()/'.local/state/lscript-updated/backups'/stamp
    backup.mkdir(parents=True)
    shutil.copy2(menu,backup/'pentest-menu')
    if config.exists(): shutil.copy2(config,backup/'tools.list')
    if runtime.exists(): shutil.copytree(runtime,backup/'runtime')
    manifest=dict(menu=str(menu),config=str(config),runtime=str(runtime),config_existed=config.exists(),runtime_existed=runtime.exists())
    (backup/'manifest.json').write_text(json.dumps(manifest,indent=2))
    with tempfile.TemporaryDirectory() as temp:
        prepared=Path(temp)/'pentest-menu'; prepared.write_text(patched)
        run(['bash','-n',str(prepared)])
        runtime.mkdir(parents=True,exist_ok=True)
        wrapper='#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, '+repr(str(PROJECT))+')\nfrom lazytoolkit.bridge import main\nmain()\n'
        (runtime/'catalog.py').write_text(wrapper)
        # Presence marker expected by the non-destructive Bash integration block.
        (runtime/'catalog.json').write_text(json.dumps({'project':str(PROJECT)}))
        for record in load_catalog()['records']:
            script='#!/bin/sh\nexec python3 '+shlex.quote(str(PROJECT/'lazy.py'))+' run '+shlex.quote(record['id'])+' -- "$@"\n'
            write_executable(runtime/'bin'/('tool-'+record['id']),script)
        config.parent.mkdir(parents=True,exist_ok=True)
        current=config.read_text() if config.exists() else ''
        command=str(PROJECT/'l')
        if not any(len(line.split('|'))==5 and line.split('|')[2]==command for line in current.splitlines()):
            current=current.rstrip()+'\nMaintenance|LScript Updated|'+command+'|helper|Unified catalog, profiles and provenance\n'
        config.write_text(current)
        try:
            install_system_file(prepared,menu)
        except BaseException:
            rollback(backup, restore_system=False)
            raise
    print(f'Integrated. Backup: {backup}')
    print(f'Rollback: {PROJECT / "l"} rollback {backup}')


def rollback(backup, *, restore_system=True):
    backup=Path(backup).expanduser().resolve()
    manifest=json.loads((backup/'manifest.json').read_text())
    if restore_system: install_system_file(backup/'pentest-menu',Path(manifest['menu']))
    config=Path(manifest['config']); runtime=Path(manifest['runtime'])
    if manifest['config_existed']: shutil.copy2(backup/'tools.list',config)
    else: config.unlink(missing_ok=True)
    if runtime.exists(): shutil.rmtree(runtime)
    if manifest['runtime_existed']: shutil.copytree(backup/'runtime',runtime)
    print('Previous launcher and registry restored. Tool folders were preserved.')
