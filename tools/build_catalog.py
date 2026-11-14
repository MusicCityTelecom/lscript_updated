#!/usr/bin/env python3
"""Build the maintained catalog from the lossless imported source inventory."""
import json
from pathlib import Path

PROJECT=Path(__file__).resolve().parents[1]
source=json.loads((PROJECT/'data/legacy-catalog.json').read_text())
records={r['id']:r for r in source['records']}
for record in records.values():
    record['commands']=[]
    if not record['categories']: record['categories']=['Legacy imports']
    for binding in record['bindings']:
        if binding['category']=='GitHub References': binding['kind']='reference'
        else: record['commands'].append(binding['command'])
    record['description']=next((b['description'] for b in record['bindings']), 'Preserved original entry; compatibility review required.')

APT={
 'nmap':('nmap','nmap'), 'tcpdump':('tcpdump','tcpdump'), 'tshark':('tshark','tshark'),
 'wireshark':('wireshark','wireshark'), 'snmpwalk':('snmp','snmpwalk'), 'smbclient':('smbclient','smbclient'),
 'ldapsearch':('ldap-utils','ldapsearch'), 'searchsploit':('exploitdb','searchsploit'),
 'arpscan':('arp-scan','arp-scan'), 'netdiscover':('netdiscover','netdiscover'), 'mtr':('mtr-tiny','mtr'),
 'iperf3':('iperf3','iperf3'), 'nbtscan':('nbtscan','nbtscan'), 'hydra':('hydra','hydra'),
 'john':('john','john'), 'hashcat':('hashcat','hashcat'), 'crunch':('crunch','crunch'),
 'sngrep':('sngrep','sngrep'), 'ngrep':('ngrep','ngrep'), 'tcpflow':('tcpflow','tcpflow'),
 'aircrackng':('aircrack-ng','aircrack-ng'), 'airodumpng':('aircrack-ng','airodump-ng'),
 'aireplayng':('aircrack-ng','aireplay-ng'), 'iw':('iw','iw'), 'rfkill':('rfkill','rfkill'),
 'kismet':('kismet','kismet'), 'wifite':('wifite','wifite'),
 'nikto':('nikto','nikto'), 'sqlmap':('sqlmap','sqlmap'), 'whatweb':('whatweb','whatweb'),
 'ffuf':('ffuf','ffuf'), 'gobuster':('gobuster','gobuster'), 'sslscan':('sslscan','sslscan'),
 'gdb':('gdb','gdb'), 'r2':('radare2','r2'), 'binwalk':('binwalk','binwalk'),
 'apktool':('apktool','apktool'), 'adb':('adb','adb'), 'fastboot':('fastboot','fastboot'),
 'yara':('yara','yara'), 'foremost':('foremost','foremost'), 'scalpel':('scalpel','scalpel'),
 'exiftool':('libimage-exiftool-perl','exiftool'), 'testdisk':('testdisk','testdisk'),
 'photorec':('testdisk','photorec'), 'cupp':('cupp','cupp'), 'ngrok':('ngrok','ngrok'),
 'geany':('geany','geany'), 'bleachbit':('bleachbit','bleachbit'),
}
for key,(package,command) in APT.items():
    if key in records:
        records[key]['recipe']={'kind':'apt','packages':[package]}
        if command not in records[key]['commands']: records[key]['commands'].append(command)

PIP={'sherlock':('sherlock-project','sherlock'), 'maigret':('maigret','maigret'),
 'arjun':('arjun','arjun'), 'wafw00f':('wafw00f','wafw00f'), 'ropgadget':('ROPGadget','ROPgadget'),
 'ropper':('ropper','ropper'), 'frida':('frida-tools','frida'), 'objection':('objection','objection'),
 'holehe':('holehe','holehe'), 'dnstwist':('dnstwist','dnstwist')}
for key,(package,entry) in PIP.items():
    if key in records: records[key]['recipe']={'kind':'pip','package':package,'entry':entry}

# New tools: one stable canonical ID per application/library, plus documented actions.
def add(key,name,description,command=None,package=None,repo=None,category='Reverse Engineering',kind='cli'):
    record=records.setdefault(key,dict(id=key,name=name,categories=[category],bindings=[],sources=[],repositories=[],commands=[]))
    record['description']=description
    record['kind']=kind
    if category not in record['categories']: record['categories'].append(category)
    if command and command not in record['commands']: record['commands'].append(command)
    if package: record['recipe']={'kind':'apt','packages':[package]}
    if repo:
        url='https://github.com/'+repo
        if url not in record['repositories']: record['repositories'].append(url)
    if not any(s['suite']=='LScript Updated' for s in record['sources']):
        record['sources'].append(dict(suite='LScript Updated',source_id=key,label=name))
    return record

add('ghidra','Ghidra','Native binary decompiler, disassembler and analysis framework.', 'ghidra',repo='NationalSecurityAgency/ghidra',kind='gui')['recipe']={
 'kind':'release','repository':'NationalSecurityAgency/ghidra','asset_pattern':r'ghidra_.*_PUBLIC_.*\.zip','entry_glob':'*/ghidraRun','format':'zip','java_min':25}
add('cutter','Cutter','Graphical reverse-engineering interface built on Rizin.', 'cutter',repo='rizinorg/cutter',kind='gui')['recipe']={
 'kind':'release','repository':'rizinorg/cutter','asset_pattern':r'.*Linux.*x86_64.*\.AppImage','format':'appimage'}
add('rizin','Rizin','Binary analysis framework and command-line reverse engineering.', 'rizin',package='rizin',repo='rizinorg/rizin')
add('r2','radare2','Command-line disassembly, debugging and binary analysis.','r2',package='radare2',repo='radareorg/radare2')
add('gdb','GDB','Native debugger.','gdb',package='gdb')
for key,name,command,package,desc in [
 ('lldb','LLDB','lldb','lldb','LLVM debugger.'), ('strace','strace','strace','strace','System-call tracing.'),
 ('ltrace','ltrace','ltrace','ltrace','Dynamic library-call tracing.'), ('readelf','readelf','readelf','binutils','ELF headers, sections and symbols.'),
 ('objdump','objdump','objdump','binutils','Object-file inspection and disassembly.'), ('nm','nm','nm','binutils','Symbol tables.'),
 ('strings','strings','strings','binutils','Extract printable strings.'), ('file','file','file','file','Identify file formats.'),
 ('xxd','xxd','xxd','xxd','Hexadecimal viewing and conversion.'), ('hexedit','Hexedit','hexedit','hexedit','Terminal hex editor.'),
 ('ghex','GHex','ghex','ghex','Graphical hex editor.'), ('patchelf','patchelf','patchelf','patchelf','Inspect/modify ELF interpreter and linkage.'),
 ('elfutils','elfutils','eu-readelf','elfutils','Additional ELF/DWARF inspection tools.'),
 ('qemuuser','QEMU user-mode','qemu-x86_64','qemu-user','User-mode CPU emulation.'),
 ('qemusystem','QEMU system emulator','qemu-system-x86_64','qemu-system-x86','Whole-system virtualization/emulation.'),
 ('squashfstools','SquashFS tools','unsquashfs','squashfs-tools','Inspect/extract SquashFS images.'),
 ('uboottools','U-Boot tools','dumpimage','u-boot-tools','Inspect U-Boot firmware images.'),
 ('dtc','Device Tree Compiler','dtc','device-tree-compiler','Inspect/convert device trees.'),
 ('binwalk','Binwalk','binwalk','binwalk','Firmware file signatures and embedded data inspection.'),
 ('yara','YARA','yara','yara','File-analysis and malware-identification rules.'),
 ('exiftool','ExifTool','exiftool','libimage-exiftool-perl','Metadata inspection.')]:
    add(key,name,desc,command,package,kind='gui' if key=='ghex' else 'cli')
add('jadx','JADX','Android DEX/APK decompilation and Java output.','jadx',repo='skylot/jadx')['recipe']={
 'kind':'release','repository':'skylot/jadx','asset_pattern':r'jadx-[0-9.]+\.zip','entry_glob':'bin/jadx','format':'zip','java_min':11}
# Existing GUI entry is retained; one application can offer a distinct GUI action.
add('jadxgui','JADX GUI','Graphical Android DEX/APK decompiler.','jadx-gui',repo='skylot/jadx',category='Mobile',kind='gui')
for key,name,repo,desc,command in [
 ('pwndbg','pwndbg','pwndbg/pwndbg','GDB/LLDB debugger enhancement.','pwndbg'),
 ('gef','GEF','hugsy/gef','GDB extension for reverse engineering and exploit development.',None),
 ('retdec','RetDec','avast/retdec','Retargetable machine-code decompiler.','retdec-decompiler'),
 ('ilspy','ILSpy / ilspycmd','icsharpcode/ILSpy','.NET assembly decompilation.','ilspycmd'),
 ('recaf','Recaf','Col-E/Recaf','Java bytecode inspection and editing.',None),
 ('detectiteasy','Detect It Easy','horsicq/Detect-It-Easy','Executable format/compiler/packer identification.','diec'),
 ('pebear','PE-bear','hasherezade/pe-bear','Portable Executable inspection.','pe-bear'),
 ('capa','capa','mandiant/capa','Identify capabilities in executable files.','capa'),
 ('floss','FLOSS','mandiant/flare-floss','Extract/decode strings from executable files.','floss'),
 ('angr','angr','angr/angr','Python binary analysis and symbolic-execution library.',None),
 ('capstone','Capstone','capstone-engine/capstone','Multi-architecture disassembly library.',None),
 ('unicorn','Unicorn','unicorn-engine/unicorn','CPU emulation library.',None),
 ('keystone','Keystone','keystone-engine/keystone','Multi-architecture assembler library.',None),
 ('qiling','Qiling','qilingframework/qiling','Cross-platform emulation framework.',None),
 ('lief','LIEF','lief-project/LIEF','Executable-format parsing/modification library.',None),
 ('pefile','pefile','erocarrera/pefile','Python PE-format inspection library.',None),
 ('pyelftools','pyelftools','eliben/pyelftools','Python ELF/DWARF inspection library.',None),
 ('emba','EMBA','e-m-b-a/emba','Firmware security analysis framework.',None),
 ('firmadyne','Firmadyne','firmadyne/firmadyne','Firmware emulation/research project.',None),
 ('factcore','FACT','fkie-cad/FACT_core','Firmware analysis and comparison platform.',None),
 ('x64dbg','x64dbg (Windows)','x64dbg/x64dbg','Windows debugger; reference on Linux.',None),
 ('jpexs','JPEXS FFDec','jindrapetrik/jpexs-decompiler','Flash/SWF decompilation and inspection.',None),
 ('reversingresources','Reverse-engineering resources','mytechnotalent/Reverse-Engineering','Training and architecture references.',None)]:
    add(key,name,desc,command,repo=repo)
records['capa']['recipe']={'kind':'pip','package':'flare-capa','entry':'capa'}
records['floss']['recipe']={'kind':'pip','package':'flare-floss','entry':'floss'}
records['cupp']['local_entries']=[{'directory':'~/Desktop/Pentest/BCHackTool/cupp','entry':'cupp.py','interpreter':'python3'}]
records['redhawk']['local_entries']=[{'directory':'~/Desktop/Pentest/BCHackTool/RED_HAWK','entry':'rhawk.php','interpreter':'php'}]
records['iptracer']['local_entries']=[{'directory':'~/Desktop/Pentest/BCHackTool/IP-Tracer','entry':'.IP-Tracer.php','interpreter':'php'}]
# JADX's GUI and CLI are actions of the same application, not duplicate installs.
gui=records.pop('jadxgui')
for binding in gui['bindings']: binding['action']='gui'
records['jadx']['bindings'].extend(gui['bindings'])
records['jadx']['sources'].extend(gui['sources'])
records['jadx']['actions']={'gui':'jadx-gui'}
records['jadx']['categories']=list(dict.fromkeys(records['jadx']['categories']+gui['categories']))
# Keep the legacy source evidence unchanged alongside enriched runtime metadata.
output=dict(schema=2,version='3.0.0',source_counts=source['counts'],records=sorted(records.values(),key=lambda r:r['id']))
(PROJECT/'data/catalog.json').write_text(json.dumps(output,indent=2)+'\n')
print('Catalog:',len(records),'unique tools;',sum(bool(r.get('recipe')) for r in records.values()),'install recipes')
