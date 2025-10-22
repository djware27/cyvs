#!/bin/bash
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

echo "=== Test 16: Software Inventory + SBOM ==="

# Use sudo only if not already root
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

# Output directory and timestamp
OUTDIR="${OUTDIR:-.}"
mkdir -p "$OUTDIR" 2>/dev/null || true
TS="$(date +%Y%m%d_%H%M%S)"

# SBOM paths
SBOM_JSON="${OUTDIR}/syft_sbom_${TS}.json"
SBOM_CDX="${OUTDIR}/syft_sbom_${TS}.cyclonedx.json"

# >>> Exclude feature: convert to Syft-compatible relative globs (./.../**)
EXCLUDES_MOUNTS_FILE="${CYVS_EXCLUDES_MOUNTS_FILE:-/etc/cyvs/excludes.mounts}"

# hard-reset arrays so nothing leaks in from earlier code
unset SYFT_EX_ARGS SYFT_EX_SHOW
declare -a SYFT_EX_ARGS SYFT_EX_SHOW

if [ -r "$EXCLUDES_MOUNTS_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    # strip comments and surrounding whitespace
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue

    # Build Syft pattern:
    # - './something/**' = already relative glob → pass through
    # - '/absolute/path' → './absolute/path/**'
    # - 'name'           → './name/**'
    if [[ "$line" == ./* ]]; then
      pat="$line"
    elif [[ "${line:0:1}" == "/" ]]; then
      rel="${line#/}"; rel="${rel%/}"
      pat="./${rel}/**"
    else
      name="${line%/}"
      pat="./${name}/**"
    fi

    SYFT_EX_ARGS+=(--exclude "$pat")
    SYFT_EX_SHOW+=("$pat")
  done < "$EXCLUDES_MOUNTS_FILE"
fi

# Confirm what Syft will actually skip (converted patterns)
#if ((${#SYFT_EX_ARGS[@]})); then
#  echo "[INFO] Syft exclude rules active (${#SYFT_EX_SHOW[@]} entries):"
#  for p in "${SYFT_EX_SHOW[@]}"; do
#    echo "  - $p"
#  done
#else
#  echo "[INFO] No Syft exclude file detected; scanning entire filesystem."
#fi

# Extra sanity: print the array exactly as passed to syft (comment out later)
declare -p SYFT_EX_ARGS | sed 's/^/[DEBUG] /'
# <<< end exclude feature

if command -v syft >/dev/null 2>&1; then
  echo "[+] Generating SBOM (JSON)…"
#  echo "CMD: $SUDO syft dir:/ ${SYFT_EX_ARGS[*]} -o json > $SBOM_JSON"
  if $SUDO syft dir:/ "${SYFT_EX_ARGS[@]}" -o json > "$SBOM_JSON"; then
    echo "[+] SBOM (JSON) saved: $SBOM_JSON"
  else
    echo "[!] syft failed to generate JSON SBOM" >&2
    SBOM_JSON=""
  fi

  echo "[+] Generating SBOM (CycloneDX JSON)…"
#  echo "CMD: $SUDO syft dir:/ ${SYFT_EX_ARGS[*]} -o cyclonedx-json > $SBOM_CDX"
  if $SUDO syft dir:/ "${SYFT_EX_ARGS[@]}" -o cyclonedx-json > "$SBOM_CDX"; then
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
# Step 17: Vulnerability Scan (Grype from SBOM)
# ----------------------------
echo "=== Step 17: Vulnerability Scan (grype from SBOM) ==="

SRC=""
if [ -n "$SBOM_CDX" ] && [ -s "$SBOM_CDX" ]; then
  SRC="sbom:${SBOM_CDX}"
elif [ -n "$SBOM_JSON" ] && [ -s "$SBOM_JSON" ]; then
  SRC="sbom:${SBOM_JSON}"
fi

GRYPE_OUT="${OUTDIR}/grype_report_${TS}.txt"
GRYPE_JSON="${OUTDIR}/grype_report_${TS}.json"

if command -v grype >/dev/null 2>&1; then
  if [ -z "$SRC" ]; then
    echo "[!] No SBOM produced by syft; grype will attempt to scan root filesystem."
    SRC="dir:/"
  fi

  echo "[+] Running grype against ${SRC} …"
  grype "$SRC" -o table | tee "$GRYPE_OUT" >/dev/null
  grype "$SRC" -o json > "$GRYPE_JSON" 2>/dev/null || true

  echo "[+] Grype reports saved:"
  echo "    - Table: $GRYPE_OUT"
  echo "    - JSON : $GRYPE_JSON"
else
  echo "[-] grype not installed. Install with:"
  echo "    curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"
fi
echo ""
echo ""
# ----------------------------
# Step 18: CVE Summary (complete totals)
# ----------------------------
echo "=== Step 18: CVE Summary ==="

if [ -s "$GRYPE_JSON" ] && command -v jq >/dev/null 2>&1; then
  TOTAL=$(jq '(.matches // []) | length' "$GRYPE_JSON")

  # Severity tallies
  CRIT=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="critical")]   | length' "$GRYPE_JSON")
  HIGH=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="high")]       | length' "$GRYPE_JSON")
  MED=$( jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="medium")]     | length' "$GRYPE_JSON")
  LOW=$( jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="low")]        | length' "$GRYPE_JSON")
  NEGL=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="negligible")] | length' "$GRYPE_JSON")
  UNK=$( jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="unknown")]    | length' "$GRYPE_JSON")

  # Fix-state tallies (note: path is .vulnerability.fix.state)
  # include a few common variants just in case
  FIXED=$(
    jq '[.matches[]? 
          | .vulnerability.fix.state // empty 
          | ascii_downcase 
          | select(.=="fixed")] 
        | length' "$GRYPE_JSON"
  )
  NOTFIX=$(
    jq '[.matches[]? 
          | .vulnerability.fix.state // empty 
          | ascii_downcase 
          | select(.=="not-fixed" or .=="notfixed")] 
        | length' "$GRYPE_JSON"
  )
  IGNORED=$(
    jq '[.matches[]? 
          | .vulnerability.fix.state // empty 
          | ascii_downcase 
          | select(.=="wont-fix" or .=="will-not-fix" or .=="deferred")] 
        | length' "$GRYPE_JSON"
  )

  echo "[+] CVE Totals:"
  printf "    Total:       %s\n" "${TOTAL:-0}"
  printf "    Critical:    %s\n" "${CRIT:-0}"
  printf "    High:        %s\n" "${HIGH:-0}"
  printf "    Medium:      %s\n" "${MED:-0}"
  printf "    Low:         %s\n" "${LOW:-0}"
  printf "    Negligible:  %s\n" "${NEGL:-0}"
  printf "    Unknown:     %s\n" "${UNK:-0}"
  printf "  \n"
  printf "  By status (from Grype JSON):\n"
  printf "    Fixed:       %s\n" "${FIXED:-0}"
  printf "    Not-fixed:   %s\n" "${NOTFIX:-0}"
  printf "    Ignored:     %s\n" "${IGNORED:-0}"

else
  echo "[-] No Grype output to summarize."
fi
