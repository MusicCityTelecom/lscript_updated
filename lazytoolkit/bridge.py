"""Adapter for the existing Bash pentest-menu; no scripts are sourced."""
import os
from pathlib import Path
import re
import sys
from .core import display_info, load_catalog, status, tool


def key_for(command):
    base = Path(command).name
    if base.startswith('tool-'): return base[5:]
    base = re.sub(r'^pentest-(source|ref)-', '', base)
    base = re.sub(r'-source$', '', base)
    key = re.sub('[^a-z0-9]', '', base.lower())
    return {'rsf':'routersploit','jadxgui':'jadx','sn1per':'sniper','rhawk':'redhawk'}.get(key,key)


def merge(text, directory):
    grouped = {}
    for line in text.splitlines():
        if not line.strip(): continue
        row = line.split('|')
        if len(row) != 5: raise ValueError('Malformed existing tool row; no entry was silently discarded.')
        key = key_for(row[2])
        old = grouped.get(key)
        if old is None or (old[3] in ('reference','gui') and row[3] in ('cli','root','helper')):
            grouped[key] = row
    for record in load_catalog()['records']:
        if record['id'] in grouped: continue
        category = record['categories'][0] if record['categories'] else 'Imported tools'
        description = record.get('description','Imported tool').replace('|','/')
        grouped[record['id']] = [category,record['name'],str(directory/'bin'/('tool-'+record['id'])),
                                  'helper',description]
    return list(grouped.values())


def main():
    action = sys.argv[1] if len(sys.argv)>1 else 'report'
    directory = Path(os.environ.get('PENTEST_MENU_INTEGRATION_DIR',
                                   str(Path.home()/'.local/share/pentest-menu-integration')))
    if action == 'merge':
        for row in merge(sys.stdin.read(), directory): print('|'.join(row))
    elif action == 'statuses':
        for record in load_catalog()['records']:
            print(str(directory/'bin'/('tool-'+record['id']))+'|'+status(record))
    elif action == 'command-info': display_info(tool(key_for(sys.argv[2])))
    else:
        catalog=load_catalog()
        print(f"LScript Updated: {len(catalog['records'])} canonical tool entries")
        print('Use lazy source LScript, lazy source BCHackTool, or lazy list.')


if __name__ == '__main__': main()
