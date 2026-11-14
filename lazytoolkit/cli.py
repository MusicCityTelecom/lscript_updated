"""Searchable, paginated terminal interface and scriptable command line."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
from . import __version__
from .core import LazyError, PROJECT, display_info, distro, execute, load_catalog, resolve, status, tool
from .installers import github_token, install, plan, download
from .integration import integrate, rollback, self_install, self_uninstall
from .profiles import PROFILES
from .workflows import metasploit, triage


def filtered(search='', category=None, source=None, installed=False):
    records=load_catalog()['records']
    if search:
        term=search.lower()
        records=[r for r in records if term in json.dumps(r).lower()]
    if category: records=[r for r in records if any(category.lower() in c.lower() for c in r['categories'])]
    if source: records=[r for r in records if any(source.lower()==s['suite'].lower() for s in r['sources'])]
    if installed: records=[r for r in records if status(r)=='installed']
    return records


def print_records(records):
    print(f"{'ID':<24} {'STATUS':<15} TOOL")
    for record in records:
        print(f"{record['id']:<24} {status(record):<15} {record['name']}")


def doctor():
    system=distro()
    print(f'LScript Updated {__version__} | Python {sys.version.split()[0]}')
    print(f"OS: {system['id']} {system['version']} | APT family supported: {system['supported']}")
    for command in ['git','python3','apt-cache','java','javac','ghidra','gdb','nmap','msfconsole']:
        print(f'{command:<12} {shutil.which(command) or "not in PATH"}')
    print('GitHub authentication: '+('configured' if github_token() else 'anonymous public access'))
    counts={}
    for record in load_catalog()['records']:
        state=status(record); counts[state]=counts.get(state,0)+1
    print('Catalog status: '+json.dumps(counts,sort_keys=True))
    print('No scanners, legacy installers or sample binaries were executed by this diagnostic.')


def sources(suite):
    rows=[]
    for record in load_catalog()['records']:
        for entry in record['sources']:
            if entry['suite'].lower()==suite.lower(): rows.append((entry,record))
    if not rows: raise LazyError('Unknown source suite. Use LScript, BCHackTool, pentest-menu or LScript Updated.')
    for entry,record in rows:
        print(f"{entry['source_id']:>6}  {entry['label']:<35} -> {record['id']} [{status(record)}]")


def action_menu(record):
    while True:
        display_info(record)
        installed = status(record) == 'installed'
        if installed:
            print('\n1 Run  2 Check installation  3 Installation plan  4 Documentation / source variants  0 Back')
        elif record.get('recipe'):
            print('\nNot installed. Choose 1 to install this tool.')
            print('1 Install  2 Install  3 Installation plan  4 Documentation / source variants  0 Back')
        else:
            print('\nNot installed. No automated installation recipe is available for this entry.')
            print('1 Repository / installation details  2 Installation details  3 Installation plan  4 Documentation / source variants  0 Back')
        choice=input('Action: ').strip()
        if choice in ('0','q',''): return
        try:
            if choice in ('1','2') and not installed:
                if record.get('recipe'):
                    install(record)
                    if status(record) == 'installed':
                        print('Installation complete. Choose Run to launch the tool.')
                else:
                    display_info(record)
            elif choice=='1':
                arguments=shlex.split(input('Arguments (quotes supported; Enter for none): '))
                execute(record,arguments)
            elif choice=='2': install(record)
            elif choice=='3': print(plan(record))
            elif choice=='4': display_info(record)
            else: print('Choose a listed action.')
        except (LazyError,ValueError,OSError) as exc: print(f'ERROR: {exc}')


def interactive():
    page,query,category,only_installed=0,'',None,False
    size=12
    paged=False
    while True:
        records=filtered(query,category,installed=only_installed)
        pages=max(1,(len(records)+size-1)//size); page=min(page,pages-1)
        offset=page*size if paged else 0
        shown=records[offset:offset+size] if paged else records
        view=f'page {page+1}/{pages}' if paged else 'full catalog'
        print(f'\nLScript Updated {__version__} — {len(records)} tools | {view}')
        print('Search: '+(query or 'all')+' | category: '+(category or 'all'))
        for index,record in enumerate(shown,offset+1):
            print(f" {index:>3}. {record['name']:<34} [{status(record)}]  {record['id']}")
        print('\nNumber or tool ID: run/install actions | install ID/NUMBER: install a selected tool')
        print('s TERM: search | c TERM: category | all: full catalog | paged: 12 per page | n/p: pages')
        print('a: clear filters | installed: toggle | d: diagnostics | profiles | q: exit')
        answer=input('lazy> ').strip()
        if answer in ('q','exit'): return
        if answer.isdecimal() and 1<=int(answer)<=len(records): action_menu(records[int(answer)-1])
        elif answer.startswith('install '):
            selected=answer[8:].strip()
            try:
                if selected.isdecimal():
                    if not 1<=int(selected)<=len(records): raise LazyError('Tool number is outside the displayed catalog.')
                    record=records[int(selected)-1]
                else: record=tool(selected)
                if not record.get('recipe') and status(record) != 'installed': display_info(record)
                else: install(record)
            except (LazyError,ValueError,OSError) as exc: print(f'ERROR: {exc}')
        elif answer=='all': paged,query,category,only_installed,page=False,'',None,False,0
        elif answer=='paged': paged=True; page=0
        elif answer=='n': page=min(page+1 if paged else 0,pages-1); paged=True
        elif answer=='p': page=max(page-1,0); paged=True
        elif answer.startswith('s '): query=answer[2:].strip(); page=0
        elif answer.startswith('c '): category=answer[2:].strip(); page=0
        elif answer=='a': query,category,page,only_installed='',None,0,False
        elif answer=='installed': only_installed=not only_installed; page=0
        elif answer=='d': doctor()
        elif answer=='profiles':
            for name,ids in PROFILES.items(): print(name+': '+', '.join(ids))
            print('Use lazy plan-profile NAME, then lazy install-profile NAME when ready.')
        elif answer:
            try: action_menu(tool(answer))
            except LazyError: print('Select a tool number, tool ID, or one of the commands.')


def parser():
    root=argparse.ArgumentParser(description='LScript Updated: shared security/reverse-engineering toolkit catalog.')
    root.add_argument('--version',action='version',version=__version__)
    sub=root.add_subparsers(dest='command')
    listing=sub.add_parser('list',help='List/search every catalog entry')
    listing.add_argument('--search',default=''); listing.add_argument('--category'); listing.add_argument('--source')
    listing.add_argument('--installed',action='store_true'); listing.add_argument('--json',action='store_true')
    info=sub.add_parser('info'); info.add_argument('tool')
    run=sub.add_parser('run'); run.add_argument('--action'); run.add_argument('tool'); run.add_argument('arguments',nargs=argparse.REMAINDER)
    for verb in ['install','plan']:
        item=sub.add_parser(verb); item.add_argument('tool'); item.add_argument('--sha256'); item.add_argument('--asset')
    sub.add_parser('doctor'); sub.add_parser('profiles')
    for verb in ['install-profile','plan-profile']:
        profile=sub.add_parser(verb); profile.add_argument('profile',choices=[*PROFILES,'all-supported'])
    source=sub.add_parser('source'); source.add_argument('suite')
    audit=sub.add_parser('audit-links'); audit.add_argument('--limit',type=int,default=20); audit.add_argument('--search',default='')
    sub.add_parser('self-install'); sub.add_parser('self-uninstall')
    bridge=sub.add_parser('integrate'); bridge.add_argument('--menu',default='/usr/local/bin/pentest-menu')
    bridge.add_argument('--apply',action='store_true'); bridge.add_argument('--preview')
    undo=sub.add_parser('rollback'); undo.add_argument('backup')
    workflow=sub.add_parser('workflow'); workflow.add_argument('name',choices=['metasploit'])
    sample=sub.add_parser('triage'); sample.add_argument('file'); sample.add_argument('--output',required=True)
    sub.add_parser('legacy-path')
    return root


def main(argv=None):
    args=parser().parse_args(argv)
    try:
        if args.command is None: interactive()
        elif args.command=='list':
            records=filtered(args.search,args.category,args.source,args.installed)
            if args.json: print(json.dumps(records,indent=2))
            else: print_records(records)
        elif args.command=='info': display_info(tool(args.tool))
        elif args.command=='run':
            arguments=args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments
            execute(tool(args.tool),arguments,action=args.action)
        elif args.command in ('install','plan'):
            install(tool(args.tool),dry_run=args.command=='plan',sha256=args.sha256,asset_name=args.asset)
        elif args.command=='doctor': doctor()
        elif args.command=='profiles':
            for name,ids in PROFILES.items(): print(name+': '+', '.join(ids))
            print('all-supported: every tool with an installation recipe (available packages vary by OS).')
        elif args.command in ('install-profile','plan-profile'):
            keys=([r['id'] for r in load_catalog()['records'] if r.get('recipe')]
                  if args.profile=='all-supported' else PROFILES[args.profile])
            failures=[]
            for key in keys:
                try: install(tool(key),dry_run=args.command=='plan-profile')
                except LazyError as exc:
                    failures.append(key); print(f'FAILED {key}: {exc}',file=sys.stderr)
            if failures: raise LazyError('Profile incomplete: '+', '.join(failures))
        elif args.command=='source': sources(args.suite)
        elif args.command=='self-install': self_install()
        elif args.command=='self-uninstall': self_uninstall()
        elif args.command=='integrate': integrate(args.menu,apply=args.apply,preview=args.preview)
        elif args.command=='rollback': rollback(args.backup)
        elif args.command=='workflow': metasploit()
        elif args.command=='triage': triage(args.file,args.output)
        elif args.command=='legacy-path': print(PROJECT/'legacy/lscript')
        elif args.command=='audit-links':
            if args.limit<1: raise LazyError('--limit must be positive.')
            urls=list(dict.fromkeys(url for record in filtered(args.search) for url in record['repositories']))[:args.limit]
            for url in urls:
                if not url.startswith('https://github.com/'): print(f'SKIP unsupported provider: {url}'); continue
                repo=url.removeprefix('https://github.com/').removesuffix('.git').strip('/')
                try:
                    metadata=json.loads(download('https://api.github.com/repos/'+repo,api=True,maximum=8*1024*1024))
                    print(f"{repo}: {'archived' if metadata.get('archived') else 'available'}")
                except LazyError as exc: print(f'{repo}: {exc}')
        return 0
    except (KeyboardInterrupt,EOFError):
        print('\nReturning from LScript Updated.'); return 130
    except (LazyError,OSError,ValueError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr); return 1
