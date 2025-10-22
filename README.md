# CYVS Security & Vulnerability Scanner

`cyvs.sh` (and its latest version `cyvs2.sh`) automates local vulnerability, package, and configuration scanning across multiple Linux distributions.  
It integrates tools like **Lynis**, **Grype**, and **Syft** to produce a comprehensive system security report.

---

## Supported Distributions

- **Debian** 12 and newer  
- **Devuan** 5 and newer  
- **Fedora** 38 and newer  
- **Arch Linux** (rolling)  
- **openSUSE Tumbleweed / SUSE Linux Enterprise (SLE)** (via zypper)

---

## Features

- Auto-detects distribution and installs dependencies automatically  
- Runs key system audit tools (`lynis`, `grype`, `syft`)  
- Collects kernel, hardware, and security configuration data  
- Supports exclusion of specified mounts or directories during scans  
- Generates structured logs and reports  
- Detects eBPF, cgroup, and kernel mitigation states  

---

## Prerequisites

### Debian / Devuan
```bash
sudo apt update
sudo apt install -y curl wget jq bpftool systemd lynis
```

### Fedora
```bash
sudo dnf install -y curl wget jq bpftool systemd lynis
```

### Arch Linux
```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm curl wget jq bpftool systemd lynis
```

### openSUSE / SLE
```bash
sudo zypper refresh
sudo zypper install -y coreutils util-linux grep procps systemd bpftool jq lynis
```

---

## Optional: Excluding Mounts from Syft/Grype Scans

`cyvs2.sh` supports excluding mount points and directories from Syft/Grype scans to improve performance and reduce noise.

**Default exclusion file path:**
```
/etc/cyvs/excludes.mounts
```

**Override with environment variable:**
```bash
export CYVS_EXCLUDES_MOUNTS_FILE=/path/to/your/excludes.mounts
```

Each non-empty, non-comment line represents a relative path to exclude.

**Example `/etc/cyvs/excludes.mounts`:**
```text
proc
sys
run/log/journal
var/lib/docker
var/lib/containers
```

The script automatically converts these to Syft exclusion patterns, e.g.:
```
--exclude "./proc/**" --exclude "./sys/**" --exclude "./run/log/journal/**"
```

This prevents scanning of ephemeral or virtual filesystems.

---

## Usage

Run the script with root privileges:
```bash
sudo bash cyvs2.sh
```

To specify a custom exclusions file:
```bash
sudo CYVS_EXCLUDES_MOUNTS_FILE=/custom/path/excludes.mounts bash cyvs2.sh
```

---

## Output

Results are saved in the working directory or `/var/log/cyvs` (if configured).

Typical output includes:
- System metadata (hostname, kernel, distribution)
- Vulnerability scan results (Grype)
- Package inventory (Syft)
- Security audit summary (Lynis)
- eBPF and cgroup configuration status

---

## Notes

- Root access is required for full-scope scans  
- Internet access is required for CVE database updates  
- Excluding virtual mounts greatly improves performance on containerized systems  
- No background daemons or persistent services are installed  

---

## License

This project is released under an open license for educational and system-hardening purposes.  
Contributions and bug fixes are welcome.
