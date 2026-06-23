#!/usr/bin/env bash
# cyvs_v2.sh — Cybergizmo Verification Script v2 (Cross-Distro)
# Purpose: Verify kernel mitigations, cgroup hierarchy, bootline safety, service health,
#          eBPF exposure, and package vulnerability exposure using Syft + Grype.
#
# v2 focus:
#   - Separates raw Grype matches from unique CVEs.
#   - Separates fixed from not-fixed exposure.
#   - Separates OS package findings from language/ecosystem findings.
#   - Shows high-confidence/direct-match findings separately.
#   - Reports CVE fan-out to reveal scanner amplification/noise.
#   - Saves machine-readable summaries for Fedora/Ubuntu comparisons.
#
# Tested target families: Debian, Ubuntu, Devuan, Arch, Fedora, RHEL-like, openSUSE, Alpine
# Copyright (c) 2025-2026 Cybergizmo
# SPDX-License-Identifier: MIT

set -o pipefail

###############################################################################
# Basic helpers
###############################################################################

have_cmd() { command -v "$1" >/dev/null 2>&1; }

safe_run() {
  # Usage: safe_run "description" command args...
  local desc="$1"; shift
  echo "--- ${desc} ---"
  "$@" 2>/dev/null || echo "[WARN] ${desc}: unavailable or failed"
}

trim_ws() {
  local s="$*"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi

OUTDIR="${OUTDIR:-.}"
mkdir -p "$OUTDIR" 2>/dev/null || true
TS="$(date +%Y%m%d_%H%M%S)"

###############################################################################
# Cross-distro detection
###############################################################################

OS_ID=unknown
OS_NAME=unknown
OS_VERSION=unknown
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
  OS_VERSION="${VERSION_ID:-unknown}"
fi

PKG_MGR=unknown
PKG_DB=unknown  # dpkg|rpm|pacman|apk

case "$OS_ID" in
  debian|ubuntu|devuan)
    PKG_MGR=apt;     PKG_DB=dpkg ;;
  fedora|rhel|centos|rocky|almalinux)
    PKG_MGR=dnf;     PKG_DB=rpm ;;
  opensuse*|suse|tumbleweed|sle)
    PKG_MGR=zypper;  PKG_DB=rpm ;;
  arch|manjaro|endeavouros)
    PKG_MGR=pacman;  PKG_DB=pacman ;;
  alpine)
    PKG_MGR=apk;     PKG_DB=apk ;;
  *)
    if have_cmd apt-get || have_cmd apt; then PKG_MGR=apt; PKG_DB=dpkg
    elif have_cmd dnf || have_cmd yum; then PKG_MGR=dnf; PKG_DB=rpm
    elif have_cmd zypper; then PKG_MGR=zypper; PKG_DB=rpm
    elif have_cmd pacman; then PKG_MGR=pacman; PKG_DB=pacman
    elif have_cmd apk; then PKG_MGR=apk; PKG_DB=apk
    fi ;;
esac

install_hint() {
  case "$PKG_MGR" in
    apt)    echo "sudo apt-get install -y $*" ;;
    dnf)    echo "sudo dnf install -y $*" ;;
    zypper) echo "sudo zypper install -y $*" ;;
    pacman) echo "sudo pacman -S --needed $*" ;;
    apk)    echo "sudo apk add $*" ;;
    *)      echo "Install '$*' with your package manager" ;;
  esac
}

list_installed_packages() {
  case "$PKG_DB" in
    dpkg)   dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort ;;
    rpm)    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort ;;
    pacman) pacman -Q 2>/dev/null | awk '{print $1 "\t" $2}' | sort ;;
    apk)    apk info -vv 2>/dev/null | awk -F- 'NF{pkg=$0; sub(/-[^-]+-[^-]+$/, "", pkg); ver=$0; sub(/.*-([^-]+-[^-]+)$/, "\\1", ver); print pkg "\t" ver}' | sort ;;
    *)      echo "# package inventory unavailable on this distro" ;;
  esac
}

###############################################################################
# Tool version capture
###############################################################################

VERSIONS_FILE="${OUTDIR}/cyvs_versions_${TS}.txt"
{
  echo "CYVS_VERSION=v2"
  echo "TIMESTAMP=${TS}"
  echo "OS_ID=${OS_ID}"
  echo "OS_NAME=${OS_NAME}"
  echo "OS_VERSION=${OS_VERSION}"
  echo "PKG_MGR=${PKG_MGR}"
  echo "PKG_DB=${PKG_DB}"
  echo "KERNEL=$(uname -r 2>/dev/null || true)"
  echo ""
  echo "--- tool versions ---"
  syft version 2>/dev/null || true
  echo ""
  grype version 2>/dev/null || true
  echo ""
  jq --version 2>/dev/null || true
} > "$VERSIONS_FILE"

###############################################################################
# Tests 1-14: platform verification
###############################################################################

echo "=== CYVS v2: Platform + Vulnerability Verification ==="
echo "[+] OS: ${OS_NAME} (${OS_ID} ${OS_VERSION})"
echo "[+] Package DB: ${PKG_DB}"
echo "[+] Output directory: ${OUTDIR}"
echo "[+] Version report: ${VERSIONS_FILE}"
echo ""

echo "=== Test 1: Check cgroup version ==="
mount | grep cgroup || echo "[WARN] no cgroup mount information found"
echo ""

echo "=== Test 2: Spectre/Meltdown Mitigation Status ==="
if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
  grep . /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null || true
else
  echo "[WARN] CPU vulnerability directory not found"
fi
echo ""

echo "=== Test 3: Kernel Command Line + Mitigation Messages ==="
cat /proc/cmdline 2>/dev/null || true
if have_cmd dmesg; then
  dmesg 2>/dev/null | grep -Ei 'Spectre|Meltdown|mitigation' | head -n 80 || true
fi
echo ""

echo "=== Test 4: Systemd Analyze ==="
if have_cmd systemd-analyze; then
  systemd-analyze 2>/dev/null || true
  systemd-analyze blame 2>/dev/null | head -n 15 || true
else
  echo "[INFO] systemd-analyze not available"
fi
echo ""

echo "=== Test 5: Kernel Version and CVE Review ==="
uname -r 2>/dev/null || true
case "$PKG_MGR" in
  dnf|zypper)
    rpm -q --changelog kernel 2>/dev/null | grep -i cve | head -n 20 || true ;;
  apt)
    echo "Debian/Ubuntu kernel CVE references:"
    echo "  - https://security-tracker.debian.org/tracker/source-package/linux"
    echo "  - https://ubuntu.com/security/cves?package=linux" ;;
  pacman)
    echo "Arch kernel CVE reference: https://security.archlinux.org/package/linux" ;;
  apk)
    echo "Alpine CVE reference: https://security.alpinelinux.org/vuln" ;;
  *)
    echo "Kernel CVE changelog not available on this package manager." ;;
esac
echo ""

echo "=== Test 6: Security Tools Audit ==="
case "$PKG_DB" in
  rpm)
    rpm -qa 2>/dev/null | grep -Ei 'selinux|audit|apparmor' || true ;;
  dpkg)
    dpkg -l 2>/dev/null | grep -Ei '^ii .*\b(selinux|audit|apparmor)' || true ;;
  pacman)
    pacman -Q 2>/dev/null | grep -Ei 'selinux|audit|apparmor' || true ;;
  apk)
    apk info -vv 2>/dev/null | grep -Ei 'selinux|audit|apparmor' || true ;;
  *)
    echo "Unknown package DB; skipping package query." ;;
esac
echo ""

echo "=== Test 7: Kernel BPF Config ==="
if [ -f /proc/config.gz ]; then
  zcat /proc/config.gz 2>/dev/null | grep CONFIG_BPF || true
elif [ -r "/boot/config-$(uname -r)" ]; then
  grep CONFIG_BPF "/boot/config-$(uname -r)" || true
else
  echo "[WARN] kernel config unavailable"
fi
echo ""

echo "=== Test 8: Show Active BPF Programs ==="
if have_cmd bpftool; then
  $SUDO bpftool prog show 2>/dev/null || echo "[WARN] bpftool prog show failed"
else
  echo "[INFO] bpftool not installed. Install with: $(install_hint bpftool)"
fi
echo ""

echo "=== Test 9: List Attached BPF Cgroup and Net Filters ==="
if have_cmd bpftool; then
  echo "-- Cgroup BPF --"
  $SUDO bpftool cgroup show /sys/fs/cgroup 2>/dev/null || true
  echo "-- Net Filters --"
  $SUDO bpftool net 2>/dev/null || true
  echo "-- XDP Programs --"
  $SUDO bpftool net show xdp 2>/dev/null || true
  echo "-- tc BPF Programs --"
  $SUDO bpftool net show tc 2>/dev/null || true
else
  echo "[INFO] bpftool not installed"
fi
echo ""

echo "=== Test 10: Rootkit Scan ==="
if have_cmd chkrootkit; then
  $SUDO chkrootkit 2>/dev/null || true
else
  echo "[INFO] chkrootkit not installed. Install with: $(install_hint chkrootkit)"
fi
echo ""

echo "=== Test 11: eBPF Loaded Maps ==="
if have_cmd bpftool; then
  $SUDO bpftool map show 2>/dev/null || true
else
  echo "[INFO] bpftool not installed"
fi
echo ""

echo "=== Test 12: systemd Services Bound to BPF ==="
if have_cmd systemctl; then
  systemctl show --property=Names --property=ExecStart --property=Slice 2>/dev/null | grep -i bpf || true
else
  echo "[INFO] systemctl not available"
fi
echo ""

echo "=== Test 13: Audit Daemon Status ==="
if have_cmd systemctl; then
  systemctl status auditd --no-pager 2>/dev/null || echo "auditd not active or unavailable"
fi
if have_cmd auditctl; then
  $SUDO auditctl -l 2>/dev/null || echo "auditctl unavailable or requires root"
else
  echo "auditctl not available"
fi
echo ""

echo "=== Test 14: List Kernel Modules Related to Security ==="
lsmod 2>/dev/null | grep -Ei 'bpf|audit|selinux|apparmor|lockdown' || true
echo ""

###############################################################################
# Test 15: Legacy CVE checker if available
###############################################################################

echo "=== Test 15: Legacy CVE Tracker if Available ==="
if have_cmd cvechecker; then
  CVECMD="cvechecker"
elif have_cmd cve-check-tool; then
  CVECMD="cve-check-tool"
else
  CVECMD=""
fi

if [ -n "$CVECMD" ]; then
  echo "[+] Initializing CVE database with ${CVECMD}..."
  $SUDO "$CVECMD" --initdbs >/dev/null 2>&1 || true

  echo "[+] Generating binary list..."
  BINLIST_FILE="${OUTDIR}/cve_binlist_${TS}.txt"
  find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null > "$BINLIST_FILE"

  echo "[+] Running legacy CVE check against binaries..."
  LEGACY_CVE_CSV="${OUTDIR}/cve_report_legacy_${TS}.csv"
  $SUDO "$CVECMD" --runcheck --fileinfo="$BINLIST_FILE" --csvoutput > "$LEGACY_CVE_CSV" 2>/dev/null || true

  if [ -s "$LEGACY_CVE_CSV" ]; then
    echo "[+] Legacy CVE report saved: $LEGACY_CVE_CSV"
    head -n 10 "$LEGACY_CVE_CSV"
  else
    echo "[-] Legacy CVE report came back empty. It may not recognize this distro's package versions."
  fi
else
  echo "[-] cvechecker/cve-check-tool not installed. Skipping test."
  echo "    Install with: $(install_hint cve-check-tool)"
fi
echo ""

###############################################################################
# Tests 16-18: Syft SBOM -> Grype -> de-amplified summaries
###############################################################################

SBOM_JSON="${OUTDIR}/syft_sbom_${TS}.json"
SBOM_CDX="${OUTDIR}/syft_sbom_${TS}.cyclonedx.json"
PKG_INVENTORY="${OUTDIR}/installed_packages_${TS}.tsv"
GRYPE_OUT="${OUTDIR}/grype_report_${TS}.txt"
GRYPE_JSON="${OUTDIR}/grype_report_${TS}.json"
SUMMARY_TXT="${OUTDIR}/cyvs_v2_summary_${TS}.txt"
SUMMARY_JSON="${OUTDIR}/cyvs_v2_summary_${TS}.json"
FANOUT_TXT="${OUTDIR}/cyvs_v2_cve_fanout_${TS}.txt"
RISK_CSV="${OUTDIR}/cyvs_v2_real_risk_${TS}.csv"

EXCLUDES_MOUNTS_FILE="${CYVS_EXCLUDES_MOUNTS_FILE:-/etc/cyvs/excludes.mounts}"
unset SYFT_EX_ARGS SYFT_EX_SHOW
declare -a SYFT_EX_ARGS SYFT_EX_SHOW

# Default excludes for pseudo filesystems and high-noise transient locations.
# These can be disabled with CYVS_DISABLE_DEFAULT_EXCLUDES=1.
if [ "${CYVS_DISABLE_DEFAULT_EXCLUDES:-0}" != "1" ]; then
  DEFAULT_EXCLUDES=(
    "/proc" "/sys" "/dev" "/run" "/tmp" "/var/tmp"
    "/mnt" "/media" "/lost+found"
    "/var/lib/containers" "/var/lib/docker" "/var/lib/flatpak"
    "/home/*/.cache" "/root/.cache"
  )
  for line in "${DEFAULT_EXCLUDES[@]}"; do
    rel="${line#/}"; rel="${rel%/}"
    pat="./${rel}/**"
    SYFT_EX_ARGS+=(--exclude "$pat")
    SYFT_EX_SHOW+=("$pat")
  done
fi

if [ -r "$EXCLUDES_MOUNTS_FILE" ]; then
  while IFS= read -r rawline || [ -n "$rawline" ]; do
    line="${rawline%%#*}"
    line="$(trim_ws "$line")"
    [ -z "$line" ] && continue

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

echo "=== Test 16: Software Inventory + SBOM ==="
echo "[+] Saving package-manager inventory: ${PKG_INVENTORY}"
list_installed_packages > "$PKG_INVENTORY"

if ((${#SYFT_EX_SHOW[@]})); then
  echo "[+] Syft exclude rules active (${#SYFT_EX_SHOW[@]} entries):"
  printf '    - %s\n' "${SYFT_EX_SHOW[@]}"
else
  echo "[INFO] No Syft exclude rules active."
fi

if have_cmd syft; then
  echo "[+] Generating Syft JSON SBOM..."
  if $SUDO syft dir:/ "${SYFT_EX_ARGS[@]}" -o json > "$SBOM_JSON"; then
    echo "[+] SBOM JSON saved: $SBOM_JSON"
  else
    echo "[!] syft failed to generate JSON SBOM" >&2
    SBOM_JSON=""
  fi

  echo "[+] Generating CycloneDX JSON SBOM..."
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
echo ""

echo "=== Step 17: Vulnerability Scan (Grype from SBOM) ==="
SRC=""
if [ -n "$SBOM_CDX" ] && [ -s "$SBOM_CDX" ]; then
  SRC="sbom:${SBOM_CDX}"
elif [ -n "$SBOM_JSON" ] && [ -s "$SBOM_JSON" ]; then
  SRC="sbom:${SBOM_JSON}"
fi

if have_cmd grype; then
  if [ -z "$SRC" ]; then
    echo "[!] No SBOM produced by Syft; Grype will scan root filesystem directly."
    SRC="dir:/"
  fi

  echo "[+] Running Grype against ${SRC}..."
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

###############################################################################
# Step 18: CVE Summary v2
###############################################################################

echo "=== Step 18: CVE Summary v2 — raw, unique, fixed, not-fixed, direct, OS-only ==="

if [ ! -s "$GRYPE_JSON" ]; then
  echo "[-] No Grype JSON output to summarize."
  exit 0
fi

if ! have_cmd jq; then
  echo "[-] jq is required for v2 summary. Install with: $(install_hint jq)"
  exit 0
fi

# Helper jq predicates embedded into each call:
#   OS package types: rpm/deb/apk/alpm; also accept package metadata pkgdb where present.
#   direct matches: anything with exact-direct-match OR exact-cpe-match OR distro-match.
#                  The exact set is reported separately so no evidence is hidden.
#   not-fixed: not-fixed/notfixed/unknown/empty are separated in output; risk uses not-fixed only by default.

RAW_TOTAL=$(jq '(.matches // []) | length' "$GRYPE_JSON")
UNIQUE_TOTAL=$(jq -r '.matches[]? | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

RAW_CRIT=$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="critical")] | length' "$GRYPE_JSON")
RAW_HIGH=$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="high")] | length' "$GRYPE_JSON")
RAW_MED=$( jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="medium")] | length' "$GRYPE_JSON")
RAW_LOW=$( jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="low")] | length' "$GRYPE_JSON")
RAW_NEGL=$(jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="negligible")] | length' "$GRYPE_JSON")
RAW_UNK=$( jq '[.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="unknown")] | length' "$GRYPE_JSON")

UNIQ_CRIT=$(jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="critical") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UNIQ_HIGH=$(jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="high") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UNIQ_MED=$( jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="medium") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UNIQ_LOW=$( jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="low") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UNIQ_NEGL=$(jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="negligible") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UNIQ_UNK=$( jq -r '.matches[]? | select((.vulnerability.severity // "unknown" | ascii_downcase)=="unknown") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

FIXED_RAW=$(jq '[.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="fixed")] | length' "$GRYPE_JSON")
NOTFIX_RAW=$(jq '[.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="notfixed")] | length' "$GRYPE_JSON")
WONTFIX_RAW=$(jq '[.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="wont-fix" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="will-not-fix" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="deferred")] | length' "$GRYPE_JSON")
FIX_UNKNOWN_RAW=$(jq '[.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="unknown" or (.vulnerability.fix.state // "" )=="")] | length' "$GRYPE_JSON")

FIXED_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="fixed") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
NOTFIX_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="notfixed") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
WONTFIX_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="wont-fix" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="will-not-fix" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="deferred") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
FIX_UNKNOWN_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="unknown" or (.vulnerability.fix.state // "" )=="") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

OS_RAW=$(jq '[.matches[]? | select((.artifact.type // "" | ascii_downcase) as $t | $t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman")] | length' "$GRYPE_JSON")
OS_UNIQ=$(jq -r '.matches[]? | select((.artifact.type // "" | ascii_downcase) as $t | $t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman") | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
LANG_RAW=$(jq '[.matches[]? | select((.artifact.type // "" | ascii_downcase) as $t | ($t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman") | not)] | length' "$GRYPE_JSON")
LANG_UNIQ=$(jq -r '.matches[]? | select((.artifact.type // "" | ascii_downcase) as $t | (($t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman") | not)) | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

DIRECT_RAW=$(jq '[.matches[]? | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase) == "exact-direct-match" or ((.type // "") | ascii_downcase) == "distro-match" or ((.type // "") | ascii_downcase) == "exact-cpe-match"))] | length' "$GRYPE_JSON")
DIRECT_UNIQ=$(jq -r '.matches[]? | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase) == "exact-direct-match" or ((.type // "") | ascii_downcase) == "distro-match" or ((.type // "") | ascii_downcase) == "exact-cpe-match")) | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')
UPSTREAM_RAW=$(jq '[.matches[]? | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase) | contains("upstream")))] | length' "$GRYPE_JSON")
UPSTREAM_UNIQ=$(jq -r '.matches[]? | select(any(.matchDetails[]?; (((.type // "") | ascii_downcase) | contains("upstream")))) | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

# Real Risk v2 definition:
#   OS package, not-fixed, direct/distro/exact-cpe match, severity critical/high.
#   This is deliberately conservative for distro comparisons.
REAL_RISK_RAW=$(jq '[.matches[]?
  | select((.artifact.type // "" | ascii_downcase) as $t | $t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman")
  | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="notfixed")
  | select((.vulnerability.severity // "unknown" | ascii_downcase)=="critical" or (.vulnerability.severity // "unknown" | ascii_downcase)=="high")
  | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase)=="exact-direct-match" or ((.type // "") | ascii_downcase)=="distro-match" or ((.type // "") | ascii_downcase)=="exact-cpe-match"))
] | length' "$GRYPE_JSON")

REAL_RISK_UNIQ=$(jq -r '.matches[]?
  | select((.artifact.type // "" | ascii_downcase) as $t | $t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman")
  | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="notfixed")
  | select((.vulnerability.severity // "unknown" | ascii_downcase)=="critical" or (.vulnerability.severity // "unknown" | ascii_downcase)=="high")
  | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase)=="exact-direct-match" or ((.type // "") | ascii_downcase)=="distro-match" or ((.type // "") | ascii_downcase)=="exact-cpe-match"))
  | .vulnerability.id // empty' "$GRYPE_JSON" | sort -u | wc -l | tr -d ' ')

# CVE fan-out table
jq -r '.matches[]? | [.vulnerability.id, (.vulnerability.severity // "unknown"), (.vulnerability.fix.state // "unknown"), (.artifact.name // "unknown"), (.artifact.version // "unknown"), (.artifact.type // "unknown"), ([.matchDetails[]?.type] | unique | join("+"))] | @tsv' "$GRYPE_JSON" \
  | awk -F'\t' '{count[$1]++; sev[$1]=$2; fix[$1]=$3} END {for (c in count) printf "%7d\t%s\t%s\t%s\n", count[c], c, sev[c], fix[c]}' \
  | sort -nr > "$FANOUT_TXT"

# Real risk CSV
{
  echo 'cve,severity,fix_state,package,version,type,match_types'
  jq -r '.matches[]?
    | select((.artifact.type // "" | ascii_downcase) as $t | $t=="rpm" or $t=="deb" or $t=="apk" or $t=="alpm" or $t=="pacman")
    | select((.vulnerability.fix.state // "unknown" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "unknown" | ascii_downcase)=="notfixed")
    | select((.vulnerability.severity // "unknown" | ascii_downcase)=="critical" or (.vulnerability.severity // "unknown" | ascii_downcase)=="high")
    | select(any(.matchDetails[]?; ((.type // "") | ascii_downcase)=="exact-direct-match" or ((.type // "") | ascii_downcase)=="distro-match" or ((.type // "") | ascii_downcase)=="exact-cpe-match"))
    | [
        (.vulnerability.id // ""),
        (.vulnerability.severity // "unknown"),
        (.vulnerability.fix.state // "unknown"),
        (.artifact.name // "unknown"),
        (.artifact.version // "unknown"),
        (.artifact.type // "unknown"),
        ([.matchDetails[]?.type] | unique | join("+"))
      ] | @csv' "$GRYPE_JSON"
} > "$RISK_CSV"

cat > "$SUMMARY_TXT" <<EOF_SUMMARY
CYVS v2 Summary
===============
Timestamp:       ${TS}
OS:              ${OS_NAME}
OS ID:           ${OS_ID}
OS Version:      ${OS_VERSION}
Kernel:          $(uname -r 2>/dev/null || true)
Package DB:      ${PKG_DB}

Raw Grype Matches
-----------------
Total raw matches:       ${RAW_TOTAL}
Critical raw matches:    ${RAW_CRIT}
High raw matches:        ${RAW_HIGH}
Medium raw matches:      ${RAW_MED}
Low raw matches:         ${RAW_LOW}
Negligible raw matches:  ${RAW_NEGL}
Unknown raw matches:     ${RAW_UNK}

Unique CVEs
-----------
Unique total CVEs:       ${UNIQUE_TOTAL}
Unique critical CVEs:    ${UNIQ_CRIT}
Unique high CVEs:        ${UNIQ_HIGH}
Unique medium CVEs:      ${UNIQ_MED}
Unique low CVEs:         ${UNIQ_LOW}
Unique negligible CVEs:  ${UNIQ_NEGL}
Unique unknown CVEs:     ${UNIQ_UNK}

Fix State
---------
Fixed raw / unique:      ${FIXED_RAW} / ${FIXED_UNIQ}
Not-fixed raw / unique:  ${NOTFIX_RAW} / ${NOTFIX_UNIQ}
Wont-fix raw / unique:   ${WONTFIX_RAW} / ${WONTFIX_UNIQ}
Unknown raw / unique:    ${FIX_UNKNOWN_RAW} / ${FIX_UNKNOWN_UNIQ}

Package Domain
--------------
OS package raw / unique:       ${OS_RAW} / ${OS_UNIQ}
Language/other raw / unique:   ${LANG_RAW} / ${LANG_UNIQ}

Match Quality
-------------
Direct/distro/exact raw / unique:    ${DIRECT_RAW} / ${DIRECT_UNIQ}
Upstream-related raw / unique:       ${UPSTREAM_RAW} / ${UPSTREAM_UNIQ}

Real Risk v2 Conservative Distro Metric
---------------------------------------
Definition: OS package + not-fixed + critical/high + direct/distro/exact-cpe match
Real-risk raw matches:   ${REAL_RISK_RAW}
Real-risk unique CVEs:   ${REAL_RISK_UNIQ}

Generated Files
---------------
Versions:        ${VERSIONS_FILE}
Package list:    ${PKG_INVENTORY}
Syft JSON:       ${SBOM_JSON}
Syft CycloneDX:  ${SBOM_CDX}
Grype table:     ${GRYPE_OUT}
Grype JSON:      ${GRYPE_JSON}
Summary text:    ${SUMMARY_TXT}
Summary JSON:    ${SUMMARY_JSON}
Fan-out table:   ${FANOUT_TXT}
Real-risk CSV:   ${RISK_CSV}
EOF_SUMMARY

cat > "$SUMMARY_JSON" <<EOF_JSON
{
  "cyvs_version": "v2",
  "timestamp": "${TS}",
  "os": {
    "name": "${OS_NAME}",
    "id": "${OS_ID}",
    "version": "${OS_VERSION}",
    "kernel": "$(uname -r 2>/dev/null || true)",
    "package_db": "${PKG_DB}"
  },
  "raw_matches": {
    "total": ${RAW_TOTAL},
    "critical": ${RAW_CRIT},
    "high": ${RAW_HIGH},
    "medium": ${RAW_MED},
    "low": ${RAW_LOW},
    "negligible": ${RAW_NEGL},
    "unknown": ${RAW_UNK}
  },
  "unique_cves": {
    "total": ${UNIQUE_TOTAL},
    "critical": ${UNIQ_CRIT},
    "high": ${UNIQ_HIGH},
    "medium": ${UNIQ_MED},
    "low": ${UNIQ_LOW},
    "negligible": ${UNIQ_NEGL},
    "unknown": ${UNIQ_UNK}
  },
  "fix_state": {
    "fixed_raw": ${FIXED_RAW},
    "fixed_unique": ${FIXED_UNIQ},
    "not_fixed_raw": ${NOTFIX_RAW},
    "not_fixed_unique": ${NOTFIX_UNIQ},
    "wont_fix_raw": ${WONTFIX_RAW},
    "wont_fix_unique": ${WONTFIX_UNIQ},
    "unknown_raw": ${FIX_UNKNOWN_RAW},
    "unknown_unique": ${FIX_UNKNOWN_UNIQ}
  },
  "package_domain": {
    "os_raw": ${OS_RAW},
    "os_unique": ${OS_UNIQ},
    "language_other_raw": ${LANG_RAW},
    "language_other_unique": ${LANG_UNIQ}
  },
  "match_quality": {
    "direct_distro_exact_raw": ${DIRECT_RAW},
    "direct_distro_exact_unique": ${DIRECT_UNIQ},
    "upstream_related_raw": ${UPSTREAM_RAW},
    "upstream_related_unique": ${UPSTREAM_UNIQ}
  },
  "real_risk_v2": {
    "definition": "OS package + not-fixed + critical/high + direct/distro/exact-cpe match",
    "raw_matches": ${REAL_RISK_RAW},
    "unique_cves": ${REAL_RISK_UNIQ}
  },
  "files": {
    "versions": "${VERSIONS_FILE}",
    "package_inventory": "${PKG_INVENTORY}",
    "syft_json": "${SBOM_JSON}",
    "syft_cyclonedx": "${SBOM_CDX}",
    "grype_table": "${GRYPE_OUT}",
    "grype_json": "${GRYPE_JSON}",
    "summary_text": "${SUMMARY_TXT}",
    "fanout_table": "${FANOUT_TXT}",
    "real_risk_csv": "${RISK_CSV}"
  }
}
EOF_JSON

cat "$SUMMARY_TXT"

echo ""
echo "=== Top 20 CVE Fan-out Amplifiers ==="
head -n 20 "$FANOUT_TXT" || true

echo ""
echo "=== Real Risk v2 Preview ==="
head -n 25 "$RISK_CSV" || true

echo ""
echo "[+] CYVS v2 complete."
echo "[+] Main summary: ${SUMMARY_TXT}"
echo "[+] Machine summary: ${SUMMARY_JSON}"
