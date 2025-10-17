# cyvs
# cyvs.sh — Cybergizmo Verification Script  
**Cross-Distro System Trust Check for Linux**

## Overview
`cyvs.sh` is a cross-distribution verification script for Debian, Devuan, Arch, and Fedora systems.  
It performs low-level integrity checks that complement **Lynis**, focusing on kernel posture, boot configuration, and vulnerability visibility.

The script is read-only — it makes no system changes.  
Its purpose is to verify that a system can be trusted **before** deployment or network exposure.

---

## Why It Was Written
Modern Linux distributions increasingly rely on **systemd** to manage core components once handled by smaller, auditable utilities.  
While convenient, this consolidation means critical behaviors — such as network management, time synchronization, service startup order, and even login handling — are now controlled by a single PID 1 process with deep integration into the kernel and user space.

This creates a challenge: users and administrators can no longer easily observe what the system is actually doing.  
`cyvs.sh` was written to restore visibility and trust by independently verifying the following:

- Kernel mitigation status (Spectre, Meltdown, etc.)  
- Whether cgroup v2 is truly enabled  
- The actual kernel bootline and any dangerous flags  
- Which services are failing or delayed during boot  
- The current vulnerability posture of installed software  

The script provides a verifiable baseline that can be checked *outside* of systemd’s own reporting chain.

---

### Observed Behavior Leading to Development
During testing across multiple Linux distributions, instances of `systemd` were observed opening or interacting with subsystems that were not directly related to the services being started.  
These included access to low-level kernel namespaces, cgroup control points, and temporary file systems in contexts where no user-initiated process required them.

While these behaviors may be benign or part of undocumented integrations, they reduce transparency and make it difficult for administrators to verify what the base system is doing.  
This lack of visibility motivated the creation of `cyvs.sh` — a standalone verification script that operates **outside of systemd’s control path** to validate:

- Kernel mitigation and security state directly from `/sys` and `/proc`  
- Active cgroup hierarchy and mount types  
- Boot parameters actually passed to the kernel  
- Service startup order and anomalies via `systemd-analyze`  
- Real-time vulnerability summaries independent of the init system

The intent is not to attack systemd, but to **restore observability** and **independent verification** for users who need to trust the integrity of their systems.

---

### Built-In Tests and Verification Coverage
`cyvs.sh` includes direct, independent tests added after repeated observations of `systemd`
opening or manipulating areas of the system that administrators traditionally expect to remain under explicit user control.  
These checks operate outside of systemd and report their results directly from kernel or filesystem data.

The verification set includes:

- **Kernel and Mitigation Status** — Reads `/sys/devices/system/cpu/vulnerabilities/*` and `dmesg` to confirm that Spectre/Meltdown protections are active and not disabled by boot flags.  
- **Bootline Inspection** — Parses `/proc/cmdline` for flags such as `mitigations=off`, `nopti`, or `nospectre_*`.  
- **Cgroup and Namespace Review** — Confirms whether `cgroup2` is in use and inspects mounts under `/sys/fs/cgroup`.  
- **Service Startup Health** — Uses `systemd-analyze` and journal queries to identify failed or stalled units.  
- **Filesystem and Mount Integrity** — Lists temporary filesystems and kernel mounts appearing during early boot.  
- **Vulnerability Snapshot** — Integrates with *Grype* (and optionally *Syft*) to summarize known CVEs.

All tests run read-only, gathering their data from kernel interfaces rather than systemd utilities.

---

### Software Package and CVE Correlation
`cyvs.sh` performs a package inventory and version check.  
Using **Grype** (and optionally **Syft**) it compares the locally installed software packages against current vulnerability databases and reports any versions known to be affected by public CVEs.

The scan summary shows counts by severity:

```
Vulnerability Summary:
  Critical: <count>
  High:     <count>
  Medium:   <count>
  Low:      <count>
```

Each count is derived from the local package list, not a remote repository, providing a view of the **actual runtime environment**.  
When `syft` is present, an SBOM is generated to improve accuracy and reduce false positives.

### Detailed Vulnerability Logs
When Grype is enabled, `cyvs.sh` runs a full vulnerability scan of the live filesystem or the installed package set and stores a complete log.  
The log lists every vulnerable package, its installed version, the fixed version (if available), and the CVE references.

Example:
```
Package: openssl
Installed Version: 3.0.14-1
Fixed Version: 3.0.15-1
CVE: CVE-2025-12345 [High]  -- Heap buffer overflow in SSL_get1_peer_certificate()
```

All detailed results are saved in timestamped files such as:
```
grype_report_2025-10-15_134522.txt
```

These reports provide an auditable record of system risk and can be archived as part of a monthly or pre-deployment verification cycle.

---

## Supported Distributions
- **Debian** 12 and newer  
- **Devuan** 5 and newer  
- **Fedora** 38 and newer  
- **Arch Linux** (rolling)

The script automatically detects the package manager (`apt`, `dnf`, or `pacman`) and adjusts accordingly.

---

## Prerequisites
### Debian / Devuan
```bash
sudo apt update
sudo apt install -y coreutils util-linux grep procps systemd bpftool jq
```
### Fedora
```bash
sudo dnf install -y coreutils util-linux grep procps-ng systemd bpftool  jq
```
### Arch Linux
```bash
sudo pacman -S coreutils util-linux grep procps-ng systemd bpf jq
```
Minimal containers may also need `bash`, `awk`, or `curl`.

---

## Optional Tools
### Install Grype (CVE Scanner)
```bash
 sudo grype db update    # update the CVE database
 curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
 curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
```

### Install Lynis (Complementary Audit)
```bash
sudo apt install -y lynis     # Debian / Devuan
sudo dnf install -y lynis     # Fedora
sudo pacman -Syu lynis        # Arch
```

---

## Usage
```bash
chmod +x cyvs.sh
sudo ./cyvs.sh | tee cyvs_$(date +%F).log
```
Run it with sudo so kernel and service data are accessible.  
Output is logged with the current date for comparison.

---

## Example Output
```
=== Cybergizmo Verification Summary ===
Cgroup: v2 detected (/sys/fs/cgroup)
Mitigations: Enabled (Spectre, Meltdown)
Bootline: Safe (no risky flags found)
Slowest service: systemd-resolved (2.3s)
Vulnerability Summary:
  Critical: 0 | High: 12 | Medium: 205 | Low: 489
```

---

## Preflight: cyvs-configure.sh (No Installs)
A companion script, `cyvs-configure.sh`, performs a preflight check **without installing anything**.  
It detects your distribution, checks for required tools, and predicts which `cyvs.sh` tests will pass, skip, or likely fail.

Run:
```bash
chmod +x cyvs-configure.sh
./cyvs-configure.sh
```

What it does:
- Detects OS and package manager  
- Checks for required commands  
- Verifies kernel interfaces and cgroup type  
- Predicts PASS / SKIP / LIKELY-FAIL for each test  
- Prints **suggested** install commands (nothing is installed automatically)

This keeps `cyvs.sh` honest and read-only while giving users a clear, actionable preview.

---

## Configuration Recommendations Policy
`cyvs.sh` is a **read-only diagnostic tool**.  
It may recommend configuration changes—such as kernel `sysctl` settings—that improve system hardening or visibility, but **it never applies those changes automatically**.

Before applying any recommendations, users should:
- Review each suggested setting in context.  
- Confirm that it will not disrupt installed packages, routing, VPNs, or other services.  
- Apply changes manually (if desired) using `/etc/sysctl.conf` or `/etc/sysctl.d/*.conf` and test on a staging system first.

This approach ensures that the script remains a **non-invasive verification tool**, preserving system integrity while still highlighting potential areas for improvement.

---

## Ongoing Development and Updates
`cyvs.sh` is an active project.  
Systemd and related subsystems continue to evolve, sometimes introducing new behaviors or accessing areas of the system not previously exposed.  
Because of this, new tests and verifications will be added as they become necessary.

Each release will include:
- Updated detection for new systemd components  
- Expanded kernel and cgroup verification  
- Revised CVE scanning logic with current Grype/Syft databases  
- Improved logging and reporting for audits  

Users are encouraged to check for new versions regularly and review the changelog for added or modified tests.

---

## License
MIT License  
Copyright © 2025 Cybergizmo  

See the [LICENSE](LICENSE) file for full terms.

---

## Repository Badges (optional)
```
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/language-shell-green.svg)]()
[![Supported: Debian | Devuan | Fedora | Arch](https://img.shields.io/badge/Supported-Debian%20%7C%20Devuan%20%7C%20Fedora%20%7C%20Arch-lightgrey.svg)]()
