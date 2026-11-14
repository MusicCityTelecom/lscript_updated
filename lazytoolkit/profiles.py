"""Profiles describe selected tools; they never execute assessments."""
PROFILES = {
    'reverse-core': ['ghidra','cutter','gdb','lldb','r2','rizin','readelf','objdump','strings','file','xxd','strace','ltrace'],
    'firmware': ['binwalk','squashfstools','uboottools','dtc','qemuuser','qemusystem','yara'],
    'mobile': ['jadx','apktool','adb','fastboot','frida','objection'],
    'file-analysis': ['file','strings','yara','exiftool','capa','floss','hexedit','patchelf','elfutils'],
    'network-core': ['nmap','tcpdump','tshark','wireshark','arpscan','mtr','iperf3','sngrep'],
    'web-core': ['ffuf','gobuster','sqlmap','whatweb','nikto','sslscan','arjun','wafw00f'],
    'osint': ['sherlock','maigret','holehe','dnstwist'],
    'forensics': ['yara','exiftool','testdisk','photorec','foremost'],
}
