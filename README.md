# LScript Updated

A maintained revival of the LAZY script for **Kali Linux, Debian and Ubuntu**,
with an English terminal interface, a shared tool catalog, reverse-engineering
profiles, and integration with an existing `pentest-menu` installation.

**Version 3.0.0:** 338 canonical catalog entries and 83 installation recipes.
These numbers describe the catalog, not bundled binaries or a claim that every
legacy project works on current distributions. Tools are installed on demand.

## What changed

- Every imported entry is preserved: 200 original `pentest-menu` rows, 21
  BCHackTool entries, and 100 LScript tool/installer definitions. Provenance stays
  attached when duplicate tools are merged.
- The original LScript files remain in `legacy/lscript/`. Historical helper
  files also remain at the root for compatibility/reference; the new launcher
  does not invoke their legacy installers.
- A paginated, searchable English interface replaces the hard-coded
  `/root/lscript` workflow. No root privileges are needed to browse the catalog.
- Existing installed binaries are reused before considering installation.
  Multiple tools that share a distro package reuse that package's binaries.
- The new reverse-engineering section covers disassembly, decompilation,
  debugging, ELF/PE inspection, firmware, Android/Java, .NET and emulation.
- APT installs use only the machine's configured repositories. Python CLI tools
  get isolated virtual environments. Upstream release downloads require SHA-256
  verification and are extracted with path/symlink checks.
- `pentest-menu` integration includes backups and rollback. Existing tool folders
  and registry entries are preserved, with one main entry per canonical tool.

## Install the launcher

Python 3.9+ and Bash are required. Clone this repository as your normal user:

```bash
git clone https://github.com/MusicCityTelecom/lscript_updated.git
cd lscript_updated
bash install.sh
```

Then run `lazy`, `l`, or `lscript`. The installer creates user-level symlinks in
`~/.local/bin` and preserves any unrelated commands already using those names.
If a name conflicts, run `./l` directly or use an available managed alias.
Keep the cloned directory in place; the symlinks point to its launcher.

If your shell does not include `~/.local/bin`, add:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

No third-party assessment tools are installed merely by installing the launcher.
Individual APT tool installs use `sudo` only when required. No Kali repositories
are added to Debian/Ubuntu, and no downloaded shell installer is piped into a shell.

## Everyday commands

```bash
lazy                         # interactive menu
lazy list --search firmware
lazy list --category 'Reverse Engineering'
lazy list --source LScript
lazy list --installed
lazy info ghidra
lazy doctor

lazy plan cutter             # describe installation; do not install
lazy install cutter          # explicitly install one selected tool
lazy run gdb -- --version
lazy run --action gui jadx   # JADX GUI is an action, not another installation

lazy profiles
lazy plan-profile reverse-core
lazy install-profile reverse-core
```

The main menu shows 12 entries per page. Use `n`/`p` for pages, `s TERM` to search,
`c TERM` to filter by category, `a` to clear filters, and a displayed number for
tool actions. Every legacy entry remains searchable even if it has no current
installation recipe.

| Status | Meaning |
|---|---|
| `installed` | A launch command was found locally |
| `installable` | A maintained recipe exists; availability still depends on OS repositories and runtime prerequisites |
| `source-only` | A source/reference viewer is available, but no native execution binding was found |
| `review-needed` | Original entry retained; no verified compatible recipe/binding has been added |

Old phishing, spam, DDoS, backdoor-generation and obsolete account-attack recipes
have not been repaired or migrated into new automation. Their original catalog
entries and upstream source history are retained. The new launcher also does not
claim to port every old LScript network-modification or exploit-chain workflow.

## Reverse-engineering profiles

| Profile | Examples |
|---|---|
| `reverse-core` | Ghidra, Cutter, GDB, LLDB, radare2, Rizin, readelf, objdump, strings, strace, ltrace |
| `firmware` | Binwalk, SquashFS, U-Boot tools, device-tree compiler, QEMU, YARA |
| `mobile` | JADX, apktool, ADB, Fastboot, Frida, Objection |
| `file-analysis` | capa, FLOSS, file, strings, YARA, ExifTool, Hexedit, patchelf, elfutils |

Additional catalog references include pwndbg, GEF, RetDec, ILSpy, Recaf,
Detect It Easy, PE-bear, angr, Capstone, Unicorn, Keystone, Qiling, LIEF,
pefile, pyelftools, EMBA, Firmadyne, FACT, x64dbg and JPEXS FFDec. Library,
Windows-only and complex source projects are explicitly distinguished from
Linux tools with automated installers. This is a broad analysis toolbox;
it does not promise to reverse engineer every possible file or protected system.

Other profiles: `network-core`, `web-core`, `osint`, `forensics`, and
`all-supported`. Review the plan before installing a large profile. Missing
packages fail with a clear message instead of silently reporting success;
profile installation reports any incomplete tools at the end.

### Ghidra and Java

The Ghidra recipe uses official NSA release assets. The current upstream source
README lists JDK 25; the installer reads `application.java.min` from the selected
release when present. It looks for a compatible installed JDK without changing
the system's Java alternatives. If one is missing, it reports the requirement.

GitHub release assets must supply a SHA-256 digest. If an older release does not,
verify its upstream checksum yourself and pass it explicitly:

```bash
lazy install ghidra --asset EXACT_RELEASE_ASSET.zip --sha256 VERIFIED_SHA256
```

Changed/ambiguous asset names fail rather than downloading an arbitrary file.
Cutter's AppImage recipe currently targets Linux x86-64 and may need AppImage/FUSE
runtime support. Other architectures must use a suitable upstream build/package.

## Workflows

```bash
lazy triage ./sample.bin --output ./analysis/sample.json
lazy workflow metasploit
```

Static triage records SHA-256, size, `file`, ELF-header and object-header output.
It does not execute the input file, recursively extract firmware, or attach a
debugger. Binary parsers still process untrusted input; run your analysis tools
in the environment appropriate to your assessment.

The Metasploit adapter launches the previously created interactive wizard,
preferring the local Desktop copy when present. Module checks/execution are
selected inside that wizard, not automatically chained by this launcher.

## Integrate into the existing pentest-menu

```bash
lazy integrate --preview ./pentest-menu.preview
lazy integrate --apply
pentest-menu
```

The integration patches the existing launcher, imports the shared catalog,
deduplicates its displayed tool rows, and adds source/provenance information.
It also repairs quoted argument handling so spaces, empty arguments and wildcard
characters are passed as data instead of being split/expanded accidentally.

Backups are stored under `~/.local/state/lscript-updated/backups/`. The command
prints an exact rollback command:

```bash
lazy rollback /absolute/path/to/backup
```

The system launcher update may request your normal `sudo` password; user
configuration and source files remain owned by your normal user. Run the new
launcher without `sudo`. Integration is optional and is not applied by installing
the launcher alone.

## Credentials and updates

Public repository metadata works anonymously. When available, GitHub API requests
reuse `GITHUB_TOKEN` or the existing BCHackTool configuration at
`~/.config/bchacktool/github.json`. No token is embedded in this repository,
download URLs or Git remotes. Tokens are not forwarded to release-download hosts.
The launcher does not grant a read-only token permission to publish repository changes.

Update this application with normal Git operations in your checkout:

```bash
git pull --ff-only
```

Tool installations are separate. Existing installed tools are reused rather than
silently overwritten. Use the appropriate package manager/upstream procedure to
upgrade tools already managed elsewhere.

## Development and verification

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_catalog.py
bash -n l install.sh uninstall.sh
```

Tests cover catalog/source preservation, command reuse, argument boundaries,
platform detection, unavailable packages, archive validation, release checksums,
Ghidra Java requirements, triage, integration and rollback. They do not execute
assessment tools against targets. CI definitions include Ubuntu/Python tests and
Kali/Debian/Ubuntu container smoke tests; passing local tests is not a claim that
those remote CI jobs or all live installations have already passed.

See [docs/VALIDATION.md](docs/VALIDATION.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and [docs/TOOL_INVENTORY.md](docs/TOOL_INVENTORY.md).

## Credits and license

Original LAZY script by arismelachroinos and upstream contributors. BCHackTool
inventory attribution: ByCh4n. Maintained fork: MusicCityTelecom.
Original LScript licensing is preserved in [LICENSE.md](LICENSE.md). New code is
provided under the same GPL-3.0 license. Third-party tools retain their own licenses.
