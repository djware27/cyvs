#!/usr/bin/env bash
# cyvs.sh — Cybergizmo Verification Script (Cross-Distro)
# Purpose: Verify kernel mitigations, cgroup hierarchy, bootline safety, service health,
#          and package vulnerability exposure (via Grype/Syft).
#
# Testied on: Debian, Devuan, Arch, Fedora
# Complements Lynis by focusing on verification areas Lynis overlooks.
#
# Copyright (c) 2025 Cybergizmo
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#!/bin/bash

# -------- Minimal cross-distro helpers (added) --------
# -------- Cross-distro detection (updated) --------
have_cmd() { command -v "$1" >/dev/null 2>&1; }

OS_ID=unknown
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
fi

PKG_MGR=unknown
PKG_DB=unknown  # dpkg|rpm|pacman|apk (useful for inventory paths)

case "$OS_ID" in
  debian|ubuntu|devuan)
    PKG_MGR=apt;     PKG_DB=dpkg
    ;;
  fedora|rhel|centos|rocky|almalinux)
    PKG_MGR=dnf;     PKG_DB=rpm
    ;;
  opensuse*|suse|tumbleweed|sle)
    PKG_MGR=zypper;  PKG_DB=rpm
    ;;
  arch|manjaro|endeavouros)
    PKG_MGR=pacman;  PKG_DB=pacman
    ;;
  alpine)
    PKG_MGR=apk;     PKG_DB=apk
    ;;
  *)
    # Fallback by probing commands (containers/minimal OS without os-release)
    if have_cmd apt-get || have_cmd apt; then PKG_MGR=apt; PKG_DB=dpkg
    elif have_cmd dnf || have_cmd yum;   then PKG_MGR=dnf; PKG_DB=rpm
    elif have_cmd zypper;                then PKG_MGR=zypper; PKG_DB=rpm
    elif have_cmd pacman;                then PKG_MGR=pacman; PKG_DB=pacman
    elif have_cmd apk;                   then PKG_MGR=apk; PKG_DB=apk
    fi
    ;;
esac

list_installed_packages() {
  case "$PKG_DB" in
    dpkg)   dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort ;;
    rpm)    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort ;;
    pacman) pacman -Q 2>/dev/null | awk '{print $1 "\t" $2}' | sort ;;
    apk)    apk info -vv 2>/dev/null | awk -F- 'NF{pkg=$0; sub(/-[^-]+-[^-]+$/, "", pkg); ver=$0; sub(/.*-([^-]+-[^-]+)$/, "\\1", ver); print pkg "\t" ver}' | sort ;;
    *)      echo "# package inventory unavailable on this distro" ;;
  esac
}

install_hint() {
  case "$PKG_MGR" in
    apt)    echo "sudo apt-get install -y $*";;
    dnf)    echo "sudo dnf install -y $*";;
    pacman) echo "sudo pacman -S --needed $*";;
    apk)    echo "sudo apk add $*";;
    *)      echo "Install '$*' with your package manager";;
  esac
}

# cve-check tool binary name differs (cvechecker vs cve-check-tool)
if have_cmd cvechecker; then
  CVECMD="cvechecker"
elif have_cmd cve-check-tool; then
  CVECMD="cve-check-tool"
else
  CVECMD=""
fi

# ------------------------------------------------------

echo "=== Test 1: Check cgroup version ==="
mount | grep cgroup

echo "=== Test 2: Spectre/Meltdown Mitigation Status ==="
grep . /sys/devices/system/cpu/vulnerabilities/*

echo "=== Test 3: Kernel Command Line ==="
cat /proc/cmdline
dmesg | grep -i 'Spectre\|Meltdown\|mitigation'

echo "=== Test 4: Systemd Analyze ==="
systemd-analyze
systemd-analyze blame | head -n 15

echo "=== Test 5: Kernel Version and CVE Review ==="
uname -r
# (modified for cross-distro)
case "$PKG_MGR" in
  dnf)
    rpm -q --changelog kernel | grep -i cve | head -n 20
    ;;
  apt)
    echo "Debian/Ubuntu kernel CVE references:"
    echo "  - https://security-tracker.debian.org/tracker/source-package/linux"
    echo "  - https://ubuntu.com/security/cves?package=linux"
    ;;
  pacman)
    echo "Arch kernel CVE references:"
    echo "  - https://security.archlinux.org/package/linux"
    ;;
  apk)
    echo "Alpine kernel CVE references:"
    echo "  - https://security.alpinelinux.org/vuln"
    ;;
  *)
    echo "Kernel CVE changelog not available on this package manager."
    ;;
esac

echo "=== Test 6: Security Tools Audit ==="
# (modified for cross-distro)
case "$PKG_MGR" in
  dnf)
    rpm -qa | grep -i selinux
    rpm -qa | grep audit
    ;;
  apt)
    dpkg -l | grep -i selinux || true
    dpkg -l | grep -E '^ii .*audit' || true
    ;;
  pacman)
    pacman -Q | grep -i selinux || true
    pacman -Q | grep -i audit || true
    ;;
  apk)
    apk info -vv 2>/dev/null | grep -i selinux || true
    apk info -vv 2>/dev/null | grep -i audit || true
    ;;
  *)
    echo "Unknown package manager; skipping package queries."
    ;;
esac

echo "=== Test 7: Kernel BPF Config ==="
if [ -f /proc/config.gz ]; then
  zcat /proc/config.gz | grep CONFIG_BPF
else
  echo "/proc/config.gz not found. Falling back to boot config..."
  grep CONFIG_BPF /boot/config-$(uname -r)
fi

echo "=== Test 8: Show Active BPF Programs ==="
bpftool prog show

echo "=== Test 9: List Attached BPF Cgroup and Net Filters ==="
echo "-- Cgroup BPF --"
bpftool cgroup show /sys/fs/cgroup
echo "-- Net Filters --"
bpftool net
echo "-- XDP Programs --"
bpftool net show xdp
echo "-- tc BPF Programs --"
bpftool net show tc

echo "=== Test 10: Rootkit Scan ==="
/usr/sbin/chkrootkit

echo "=== Test 11: eBPF Loaded Maps (Memory Locks) ==="
bpftool map show

echo "=== Test 12: systemd Services Bound to BPF ==="
systemctl show --property=Names --property=ExecStart --property=Slice | grep -i bpf

echo "=== Test 13: Audit Daemon (auditd) Status ==="
systemctl status auditd || echo "auditd not active"
auditctl -l 2>/dev/null || echo "auditctl not available"

echo "=== Test 14: List Kernel Modules Related to Security ==="

lsmod | grep -E 'bpf|audit|selinux|apparmor|lockdown'

echo "=== Test 15: CVE Tracker if Available ==="

if [ -n "$CVECMD" ]; then
    echo "[+] Initializing CVE database..."
    sudo "$CVECMD" --initdbs >/dev/null 2>&1

    echo "[+] Generating binary list..."
    BINLIST_FILE="./cve_binlist.txt"
    find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null > "$BINLIST_FILE"

    echo "[+] Running CVE check against binaries..."
    # command name differs but flags are the same for the common tool
    sudo "$CVECMD" --runcheck --fileinfo="$BINLIST_FILE" --csvoutput > cve_report.csv

    if [ -s "cve_report.csv" ]; then
        echo "[+] CVE report saved to cve_report.csv"
        echo "[+] Showing top 10 entries:"
        head -n 10 cve_report.csv
    else
        echo "[-] CVE report came back empty. It may not recognize the distro's package versions."
    fi
else
    echo "[-] cvechecker/cve-check-tool not installed. Skipping test."
    echo "    Install with: $(install_hint cve-check-tool)"
fi

###############################################################################
# Step 16–18: Syft SBOM → Grype Scan → Clean CVE Summary
###############################################################################

# ----------------------------
# Step 16: Software Inventory (Syft → SBOM)
# ----------------------------
echo "=== Step 16: Software Inventory (syft SBOM) ==="

# Optional offline mode: export CYVS_OFFLINE=1 before running
[ -n "${CYVS_OFFLINE:-}" ] && export SYFT_CHECK_FOR_APP_UPDATE=false GRYPE_DB_AUTO_UPDATE=false

# Use sudo only if not already root
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

# Output directory and timestamp
OUTDIR="${OUTDIR:-.}"
mkdir -p "$OUTDIR" 2>/dev/null || true
TS="$(date +%Y%m%d_%H%M%S)"

# SBOM paths
SBOM_JSON="${OUTDIR}/syft_sbom_${TS}.json"
SBOM_CDX="${OUTDIR}/syft_sbom_${TS}.cyclonedx.json"

if command -v syft >/dev/null 2>&1; then
  echo "[+] Generating SBOM (JSON)…"
  if $SUDO syft dir:/ -o json > "$SBOM_JSON"; then
    echo "[+] SBOM saved: $SBOM_JSON"
  else
    echo "[!] syft failed to generate JSON SBOM" >&2
    SBOM_JSON=""
  fi

  echo "[+] Generating SBOM (CycloneDX JSON)…"
  if $SUDO syft dir:/ -o cyclonedx-json > "$SBOM_CDX"; then
    echo "[+] CycloneDX SBOM saved: $SBOM_CDX"
  else
    echo "[!] syft failed to generate CycloneDX SBOM" >&2
    SBOM_CDX=""
  fi
else
  echo "[-] syft not installed. Install with:"
  echo "    curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin"
fi

# ----------------------------
# Step 17: Vulnerability Scan (Grype ← SBOM)
# ----------------------------
echo "=== Step 17: Vulnerability Scan (grype from SBOM) ==="

# Grype outputs
GRYPE_OUT="${OUTDIR}/grype_report_${TS}.txt"
GRYPE_JSON="${OUTDIR}/grype_report_${TS}.json"

if command -v grype >/dev/null 2>&1; then
  # Prefer JSON SBOM; then CycloneDX; else fall back to live filesystem scan
  if [ -n "$SBOM_JSON" ] && [ -s "$SBOM_JSON" ]; then
    SRC="sbom:${SBOM_JSON}"
  elif [ -n "$SBOM_CDX" ] && [ -s "$SBOM_CDX" ]; then
    SRC="sbom:${SBOM_CDX}"
  else
    echo "[!] SBOM not found; falling back to direct filesystem scan (slower)."
    SRC="dir:/"
  fi

  echo "[+] Running grype against ${SRC} …"
  # Human-readable table for terminal + file
  grype "$SRC" -o table | tee "$GRYPE_OUT" >/dev/null
  # Machine-parsable JSON for clean summary
  grype "$SRC" -o json > "$GRYPE_JSON" 2>/dev/null || true

  echo "[+] Grype report saved: $GRYPE_OUT"
  [ -s "$GRYPE_JSON" ] && echo "[+] Grype JSON saved:  $GRYPE_JSON"
else
  echo "[-] grype not installed. Install with:"
  echo "    curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"
fi

# ----------------------------
# Step 18: CVE Summary (complete totals)
# ----------------------------
echo "=== Step 18: CVE Summary ==="

if [ -s "$GRYPE_JSON" ] && command -v jq >/dev/null 2>&1; then
  TOTAL=$(jq '(.matches // []) | length' "$GRYPE_JSON")

  CRIT=$(jq '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="critical"))   | length' "$GRYPE_JSON")
  HIGH=$(jq '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="high"))       | length' "$GRYPE_JSON")
  MED=$(jq  '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="medium"))     | length' "$GRYPE_JSON")
  LOW=$(jq  '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="low"))        | length' "$GRYPE_JSON")
  NEGL=$(jq '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="negligible")) | length' "$GRYPE_JSON")
  UNK=$(jq  '[.matches[].vulnerability.severity // "" | ascii_downcase] | map(select(.=="unknown"))    | length' "$GRYPE_JSON")

  FIXED=$(jq   '[.matches[].vulnerability.fix.state // "" | ascii_downcase] | map(select(.=="fixed"))     | length' "$GRYPE_JSON")
  NOTFIX=$(jq  '[.matches[].vulnerability.fix.state // "" | ascii_downcase] | map(select(.=="not-fixed")) | length' "$GRYPE_JSON")
  IGNORED=$(jq '[.matches[] | select((.ignored // false) == true)] | length' "$GRYPE_JSON")

  SUM_STATUS=$(( FIXED + NOTFIX + IGNORED ))
  NOSTATUS=$(( TOTAL - SUM_STATUS ))

  printf "  Total matches: %s\n" "$TOTAL"
  printf "  \n"
  printf "  By severity:\n"
  printf "    Critical:    %s\n" "$CRIT"
  printf "    High:        %s\n" "$HIGH"
  printf "    Medium:      %s\n" "$MED"
  printf "    Low:         %s\n" "$LOW"
  printf "    Negligible:  %s\n" "$NEGL"
  printf "    Unknown:     %s\n" "$UNK"
  printf "  \n"
  printf "  By status:\n"
  printf "    Fixed:       %s\n" "$FIXED"
  printf "    Not-fixed:   %s\n" "$NOTFIX"
  printf "    Ignored:     %s\n" "$IGNORED"
  if [ "$NOSTATUS" -ne 0 ]; then
    printf "    No-status:   %s\n" "$NOSTATUS"
  fi

elif [ -s "$GRYPE_OUT" ]; then
  # Fallback to table output if JSON missing
  sev_line=$(grep -m1 'by severity:' "$GRYPE_OUT" || true)
  stat_line=$(grep -m1 'by status:' "$GRYPE_OUT" || true)

  CRIT=$(printf "%s\n" "$sev_line" | sed -n 's/.*by severity:[[:space:]]*\([0-9]\+\)[[:space:]]*critical.*/\1/p')
  HIGH=$(printf "%s\n" "$sev_line" | sed -n 's/.*critical,[[:space:]]*\([0-9]\+\)[[:space:]]*high.*/\1/p')
  MED=$(printf "%s\n"  "$sev_line" | sed -n 's/.*high,[[:space:]]*\([0-9]\+\)[[:space:]]*medium.*/\1/p')
  LOW=$(printf "%s\n"  "$sev_line" | sed -n 's/.*medium,[[:space:]]*\([0-9]\+\)[[:space:]]*low.*/\1/p')
  NEGL=$(printf "%s\n" "$sev_line" | sed -n 's/.*low,[[:space:]]*\([0-9]\+\)[[:space:]]*negligible.*/\1/p')
  UNK=$(printf "%s\n"  "$sev_line" | sed -n 's/.*negligible,[[:space:]]*\([0-9]\+\)[[:space:]]*unknown.*/\1/p')

  FIXED=$(printf "%s\n" "$stat_line" | sed -n 's/.*by status:[[:space:]]*\([0-9]\+\)[[:space:]]*fixed.*/\1/p')
  NOTFIX=$(printf "%s\n" "$stat_line" | sed -n 's/.*fixed,[[:space:]]*\([0-9]\+\)[[:space:]]*not-fixed.*/\1/p')
  IGNORED=$(printf "%s\n" "$stat_line" | sed -n 's/.*not-fixed,[[:space:]]*\([0-9]\+\)[[:space:]]*ignored.*/\1/p')

  # We cannot reliably get TOTAL from the table lines alone if they wrap; suppress it here.
  printf "  By severity (from table):\n"
  printf "    Critical:    %s\n" "${CRIT:-0}"
  printf "    High:        %s\n" "${HIGH:-0}"
  printf "    Medium:      %s\n" "${MED:-0}"
  printf "    Low:         %s\n" "${LOW:-0}"
  printf "    Negligible:  %s\n" "${NEGL:-0}"
  printf "    Unknown:     %s\n" "${UNK:-0}"
  printf "  \n"
  printf "  By status (from table):\n"
  printf "    Fixed:       %s\n" "${FIXED:-0}"
  printf "    Not-fixed:   %s\n" "${NOTFIX:-0}"
  printf "    Ignored:     %s\n" "${IGNORED:-0}"
else
  echo "[-] No Grype output to summarize."
fi
