# Vulu

Vulu is a remote package scanner for Linux hosts. It connects to targets over SSH and enumerates installed packages using rpm or dpkg (more to follow soon). Collected package names and version information are checked against the [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/) API to find known CVEs.

With this project, we aim to provide a scanner that uses a CVE database in EU.

Vulu is based on [YALTF](https://github.com/yaltf/yaltf) which collects license information of packages over SSH.

## License

Copyright 2026 Cortex Security S.A. Licensed under GPL-3.0-only. See [LICENSE](LICENSE) for details.
