# Validation record

Local environment: Ubuntu 24.04, Python 3.12, Bash and ShellCheck.

- 29 offline unit/integration tests passed at initial validation.
- Source coverage checks retain all 200 pentest-menu rows, all 21 BCHackTool
  entries and all 100 LScript tool/installer definitions.
- Catalog contains 338 canonical entries and 83 installer recipes.
- Local diagnostics initially found 196 installed command bindings, 11 additional
  installable tools, nine source-only bindings and 122 review-needed entries.
  These are host-specific observations, not universal installation counts.
- Bash argument tests exercise spaces, empty arguments, wildcard characters,
  literal command-substitution text and malformed quoting without running targets.
- Integration/rollback tests use a temporary launcher and temporary user registry.
  The real `/usr/local/bin/pentest-menu` and Desktop tool directories were not
  modified by these tests.
- Release/Java/archive tests use fixture downloads and mock external operations.

Not yet established: live installation of every recipe, current availability of
every legacy repository/API, Kali or Debian runtime behavior, remote CI outcomes,
or successful execution of every third-party application. CI configurations and
clear failure paths are included so those checks can be expanded transparently.
