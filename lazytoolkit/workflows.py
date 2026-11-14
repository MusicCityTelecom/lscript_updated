"""Static triage and adapters for existing interactive workflows."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import datetime as dt
from .core import LazyError, PROJECT, run


def triage(filename, output):
    sample = Path(filename).expanduser().resolve()
    if not sample.is_file(): raise LazyError('Input must be a regular file.')
    digest = hashlib.sha256()
    with sample.open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''): digest.update(block)
    result = dict(file=str(sample), size_bytes=sample.stat().st_size, sha256=digest.hexdigest(),
                  timestamp=dt.datetime.now(dt.timezone.utc).isoformat(), commands=[])
    for argv in [['file','--',str(sample)], ['readelf','-h','--',str(sample)],
                 ['objdump','-f','--',str(sample)]]:
        if not shutil.which(argv[0]):
            result['commands'].append(dict(command=argv, status='not-installed')); continue
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, errors='replace', timeout=30)
            result['commands'].append(dict(command=argv, exit_code=completed.returncode,
                                           stdout=completed.stdout[:100000], stderr=completed.stderr[:10000]))
        except subprocess.TimeoutExpired:
            result['commands'].append(dict(command=argv,status='timeout'))
    # No execution of the input sample, no recursive extraction, no debugger attachment.
    target = Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.resolve() == sample: raise LazyError('Output must not overwrite the input sample.')
    target.write_text(json.dumps(result, indent=2)+'\n')
    print(f'Static triage saved: {target}')


def metasploit():
    candidates = [Path.home()/'Desktop/Pentest/Metasploit_Workflow_Wizard/msf_wizard.rc',
                  PROJECT/'workflows/msf_wizard.rc']
    resource = next((p for p in candidates if p.is_file()), None)
    if not resource: raise LazyError('Metasploit wizard resource was not found.')
    run(['msfconsole','-q','-r',str(resource)])
