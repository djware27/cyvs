#!/bin/bash
# cyvs_v3_3.sh — Cybergizmo Verification Script (Cross-Distro)
# v3.3: normal distros use Syft + Grype; atomic/OSTree/rpm-ostree distros use Trivy.
# v3.2 fix: Linux kernel CPE matches are classified separately and included in real-risk logic.
# v3.3 fix: Atomic/Trivy real-risk model uses Trivy Severity/Status/FixedVersion across ecosystems,
#             separates OS/package, language, Go binary, OSTree deployment/repo, user-home/container storage,
#             and removes undefined kernel counters from Trivy JSON summary.
# SPDX-License-Identifier: MIT
#
# Informational use only. No guarantees. Use at your own risk.

set +e

have_cmd() { command -v "$1" >/dev/null 2>&1; }

OS_ID=unknown; OS_NAME=unknown; OS_VERSION=unknown
if [ -r /etc/os-release ]; then
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_NAME="${PRETTY_NAME:-unknown}"
  OS_VERSION="${VERSION_ID:-unknown}"
fi

PKG_MGR=unknown; PKG_DB=unknown
case "$OS_ID" in
  debian|ubuntu|devuan) PKG_MGR=apt; PKG_DB=dpkg ;;
  fedora|rhel|centos|rocky|almalinux) PKG_MGR=dnf; PKG_DB=rpm ;;
  opensuse*|suse|tumbleweed|sle) PKG_MGR=zypper; PKG_DB=rpm ;;
  arch|manjaro|endeavouros) PKG_MGR=pacman; PKG_DB=pacman ;;
  alpine) PKG_MGR=apk; PKG_DB=apk ;;
  *)
    if have_cmd apt-get || have_cmd apt; then PKG_MGR=apt; PKG_DB=dpkg
    elif have_cmd dnf || have_cmd yum; then PKG_MGR=dnf; PKG_DB=rpm
    elif have_cmd zypper; then PKG_MGR=zypper; PKG_DB=rpm
    elif have_cmd pacman; then PKG_MGR=pacman; PKG_DB=pacman
    elif have_cmd apk; then PKG_MGR=apk; PKG_DB=apk
    fi ;;
esac

list_installed_packages() {
  case "$PKG_DB" in
    dpkg) dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort ;;
    rpm) rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort ;;
    pacman) pacman -Q 2>/dev/null | awk '{print $1 "\t" $2}' | sort ;;
    apk) apk info -vv 2>/dev/null | awk -F- 'NF{pkg=$0; sub(/-[^-]+-[^-]+$/, "", pkg); ver=$0; sub(/.*-([^-]+-[^-]+)$/, "\\1", ver); print pkg "\t" ver}' | sort ;;
    *) echo "# package inventory unavailable on this distro" ;;
  esac
}

install_hint() {
  case "$PKG_MGR" in
    apt) echo "sudo apt-get install -y $*" ;;
    dnf) echo "sudo dnf install -y $*" ;;
    pacman) echo "sudo pacman -S --needed $*" ;;
    apk) echo "sudo apk add $*" ;;
    *) echo "Install '$*' with your package manager" ;;
  esac
}

if have_cmd cvechecker; then CVECMD=cvechecker
elif have_cmd cve-check-tool; then CVECMD=cve-check-tool
else CVECMD=""
fi

if [ "$(id -u)" -ne 0 ]; then SUDO=sudo; else SUDO=""; fi
OUTDIR="${OUTDIR:-.}"; mkdir -p "$OUTDIR" 2>/dev/null || true
TS="$(date +%Y%m%d_%H%M%S)"
VERSIONS_FILE="${OUTDIR}/cyvs_versions_${TS}.txt"
PKG_LIST="${OUTDIR}/installed_packages_${TS}.tsv"

###############################################################################
# Test 1-15: Original verification flow
###############################################################################

echo "=== CYVS v3 Starting ==="
echo "Timestamp: $TS"
echo "OS:        $OS_NAME"
echo "OS ID:     $OS_ID"
echo "Version:   $OS_VERSION"
echo "Kernel:    $(uname -r)"
echo ""

echo "=== Toolchain Versions ===" | tee "$VERSIONS_FILE"
{
  echo "Timestamp: $TS"
  echo "OS: $OS_NAME"
  echo "OS_ID: $OS_ID"
  echo "OS_VERSION: $OS_VERSION"
  echo "Kernel: $(uname -r)"
  echo ""
  echo "--- hostnamectl ---"; hostnamectl 2>/dev/null || true
  echo ""
  echo "--- syft version ---"; syft version 2>/dev/null || echo "syft not installed"
  echo ""
  echo "--- grype version ---"; grype version 2>/dev/null || echo "grype not installed"
  echo ""
  echo "--- grype db status ---"; grype db status 2>/dev/null || echo "grype db status unavailable"
  echo ""
  echo "--- trivy version ---"; trivy --version 2>/dev/null || echo "trivy not installed"
} >> "$VERSIONS_FILE"

echo "[+] Saving package-manager inventory: $PKG_LIST"
list_installed_packages > "$PKG_LIST"

echo "=== Test 1: Check cgroup version ==="
mount | grep cgroup || true

echo "=== Test 2: Spectre/Meltdown Mitigation Status ==="
grep . /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null || echo "CPU vulnerability files unavailable"

echo "=== Test 3: Kernel Command Line ==="
cat /proc/cmdline 2>/dev/null || true
dmesg 2>/dev/null | grep -i 'Spectre\|Meltdown\|mitigation' || true

echo "=== Test 4: Systemd Analyze ==="
if have_cmd systemd-analyze; then
  systemd-analyze 2>/dev/null || true
  systemd-analyze blame 2>/dev/null | head -n 15 || true
else
  echo "systemd-analyze not available"
fi

echo "=== Test 5: Kernel Version and CVE Review ==="
uname -r
case "$PKG_MGR" in
  dnf) rpm -q --changelog kernel 2>/dev/null | grep -i cve | head -n 20 || true ;;
  apt)
    echo "Debian/Ubuntu kernel CVE references:"
    echo "  - https://security-tracker.debian.org/tracker/source-package/linux"
    echo "  - https://ubuntu.com/security/cves?package=linux" ;;
  pacman) echo "Arch kernel CVE references: https://security.archlinux.org/package/linux" ;;
  apk) echo "Alpine kernel CVE references: https://security.alpinelinux.org/vuln" ;;
  *) echo "Kernel CVE changelog not available on this package manager." ;;
esac

echo "=== Test 6: Security Tools Audit ==="
case "$PKG_MGR" in
  dnf) rpm -qa 2>/dev/null | grep -i selinux || true; rpm -qa 2>/dev/null | grep audit || true ;;
  apt) dpkg -l 2>/dev/null | grep -i selinux || true; dpkg -l 2>/dev/null | grep -E '^ii .*audit' || true ;;
  pacman) pacman -Q 2>/dev/null | grep -i selinux || true; pacman -Q 2>/dev/null | grep -i audit || true ;;
  apk) apk info -vv 2>/dev/null | grep -i selinux || true; apk info -vv 2>/dev/null | grep -i audit || true ;;
  *) echo "Unknown package manager; skipping package queries." ;;
esac

echo "=== Test 7: Kernel BPF Config ==="
if [ -f /proc/config.gz ]; then zcat /proc/config.gz | grep CONFIG_BPF || true
elif [ -r "/boot/config-$(uname -r)" ]; then grep CONFIG_BPF "/boot/config-$(uname -r)" || true
else echo "Kernel config not found."
fi

echo "=== Test 8: Show Active BPF Programs ==="
if have_cmd bpftool; then $SUDO bpftool prog show 2>/dev/null || true; else echo "bpftool not installed"; fi

echo "=== Test 9: List Attached BPF Cgroup and Net Filters ==="
if have_cmd bpftool; then
  echo "-- Cgroup BPF --"; $SUDO bpftool cgroup show /sys/fs/cgroup 2>/dev/null || true
  echo "-- Net Filters --"; $SUDO bpftool net 2>/dev/null || true
  echo "-- XDP Programs --"; $SUDO bpftool net show xdp 2>/dev/null || true
  echo "-- tc BPF Programs --"; $SUDO bpftool net show tc 2>/dev/null || true
else echo "bpftool not installed"
fi

echo "=== Test 10: Rootkit Scan ==="
if [ -x /usr/sbin/chkrootkit ]; then $SUDO /usr/sbin/chkrootkit || true
elif have_cmd chkrootkit; then $SUDO chkrootkit || true
else echo "chkrootkit not installed"
fi

echo "=== Test 11: eBPF Loaded Maps (Memory Locks) ==="
if have_cmd bpftool; then $SUDO bpftool map show 2>/dev/null || true; else echo "bpftool not installed"; fi

echo "=== Test 12: systemd Services Bound to BPF ==="
if have_cmd systemctl; then systemctl show --property=Names --property=ExecStart --property=Slice 2>/dev/null | grep -i bpf || true; else echo "systemctl not available"; fi

echo "=== Test 13: Audit Daemon (auditd) Status ==="
if have_cmd systemctl; then systemctl status auditd 2>/dev/null || echo "auditd not active"; fi
auditctl -l 2>/dev/null || echo "auditctl not available"

echo "=== Test 14: List Kernel Modules Related to Security ==="
lsmod 2>/dev/null | grep -E 'bpf|audit|selinux|apparmor|lockdown' || true

echo "=== Test 15: CVE Tracker if Available ==="
if [ -n "$CVECMD" ]; then
  echo "[+] Initializing CVE database..."
  $SUDO "$CVECMD" --initdbs >/dev/null 2>&1
  BINLIST_FILE="${OUTDIR}/cve_binlist_${TS}.txt"
  echo "[+] Generating binary list: $BINLIST_FILE"
  find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null > "$BINLIST_FILE"
  echo "[+] Running CVE check against binaries..."
  $SUDO "$CVECMD" --runcheck --fileinfo="$BINLIST_FILE" --csvoutput > "${OUTDIR}/cve_report_${TS}.csv" 2>/dev/null || true
  if [ -s "${OUTDIR}/cve_report_${TS}.csv" ]; then
    echo "[+] CVE report saved to ${OUTDIR}/cve_report_${TS}.csv"
    head -n 10 "${OUTDIR}/cve_report_${TS}.csv"
  else
    echo "[-] CVE report came back empty. It may not recognize the distro's package versions."
  fi
else
  echo "[-] cvechecker/cve-check-tool not installed. Skipping test."
  echo "    Install with: $(install_hint cve-check-tool)"
fi

###############################################################################
# Scanner Selection Logic
###############################################################################

IS_ATOMIC=0; ATOMIC_REASON=""
if have_cmd rpm-ostree; then IS_ATOMIC=1; ATOMIC_REASON="rpm-ostree command found"
elif [ -d /ostree ]; then IS_ATOMIC=1; ATOMIC_REASON="/ostree directory found"
elif [ -d /sysroot/ostree ]; then IS_ATOMIC=1; ATOMIC_REASON="/sysroot/ostree directory found"
elif grep -qi 'VARIANT_ID=.*\(silverblue\|kinoite\|sericea\|onyx\|coreos\)' /etc/os-release 2>/dev/null; then IS_ATOMIC=1; ATOMIC_REASON="atomic Fedora variant detected in /etc/os-release"
fi

if [ "$IS_ATOMIC" -eq 1 ]; then SCANNER=trivy; else SCANNER=grype; fi

echo "=== Scanner Selection ==="
if [ "$IS_ATOMIC" -eq 1 ]; then
  echo "[+] Atomic/OSTree distro detected: yes"
  echo "[+] Reason: $ATOMIC_REASON"
  echo "[+] Scanner selected: Trivy rootfs mode"
  echo "[+] Syft + Grype skipped to avoid OSTree SBOM/OOM behavior"
else
  echo "[+] Atomic/OSTree distro detected: no"
  echo "[+] Scanner selected: Syft + Grype"
fi

SUMMARY_TXT="${OUTDIR}/cyvs_v3_summary_${TS}.txt"
SUMMARY_JSON="${OUTDIR}/cyvs_v3_summary_${TS}.json"
FANOUT_TXT="${OUTDIR}/cyvs_v3_cve_fanout_${TS}.txt"
REAL_RISK_CSV="${OUTDIR}/cyvs_v3_real_risk_${TS}.csv"

###############################################################################
# Grype/Syft backend for standard distros
###############################################################################

if [ "$SCANNER" = "grype" ]; then
  echo "=== Test 16: Software Inventory + SBOM ==="
  SBOM_JSON="${OUTDIR}/syft_sbom_${TS}.json"
  SBOM_CDX="${OUTDIR}/syft_sbom_${TS}.cyclonedx.json"
  EXCLUDES_MOUNTS_FILE="${CYVS_EXCLUDES_MOUNTS_FILE:-/etc/cyvs/excludes.mounts}"
  unset SYFT_EX_ARGS SYFT_EX_SHOW
  declare -a SYFT_EX_ARGS SYFT_EX_SHOW
  DEFAULT_EXCLUDES=("/proc" "/sys" "/dev" "/run" "/tmp" "/var/tmp" "/mnt" "/media" "/lost+found" "/var/lib/containers" "/var/lib/docker" "/var/lib/flatpak" "/home/*/.cache" "/root/.cache")
  if [ -r "$EXCLUDES_MOUNTS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
      [ -z "$line" ] && continue
      DEFAULT_EXCLUDES+=("$line")
    done < "$EXCLUDES_MOUNTS_FILE"
  fi
  for line in "${DEFAULT_EXCLUDES[@]}"; do
    if [[ "$line" == ./* ]]; then pat="$line"
    elif [[ "${line:0:1}" == "/" ]]; then rel="${line#/}"; rel="${rel%/}"; pat="./${rel}/**"
    else name="${line%/}"; pat="./${name}/**"
    fi
    SYFT_EX_ARGS+=(--exclude "$pat"); SYFT_EX_SHOW+=("$pat")
  done
  echo "[+] Syft exclude rules active (${#SYFT_EX_SHOW[@]} entries):"
  for p in "${SYFT_EX_SHOW[@]}"; do echo "    - $p"; done

  if have_cmd syft; then
    echo "[+] Generating Syft JSON SBOM..."
    $SUDO syft dir:/ "${SYFT_EX_ARGS[@]}" -o json > "$SBOM_JSON" || SBOM_JSON=""
    [ -n "$SBOM_JSON" ] && echo "[+] SBOM JSON saved: $SBOM_JSON"
    echo "[+] Generating CycloneDX JSON SBOM..."
    $SUDO syft dir:/ "${SYFT_EX_ARGS[@]}" -o cyclonedx-json > "$SBOM_CDX" || SBOM_CDX=""
    [ -n "$SBOM_CDX" ] && echo "[+] CycloneDX SBOM saved: $SBOM_CDX"
  else
    echo "[-] syft not installed. Install with: curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin"
  fi

  echo "=== Step 17: Vulnerability Scan (Grype from SBOM) ==="
  SRC=""
  [ -n "$SBOM_CDX" ] && [ -s "$SBOM_CDX" ] && SRC="sbom:${SBOM_CDX}"
  [ -z "$SRC" ] && [ -n "$SBOM_JSON" ] && [ -s "$SBOM_JSON" ] && SRC="sbom:${SBOM_JSON}"
  GRYPE_OUT="${OUTDIR}/grype_report_${TS}.txt"
  GRYPE_JSON="${OUTDIR}/grype_report_${TS}.json"
  if have_cmd grype; then
    [ -z "$SRC" ] && echo "[!] No SBOM produced by syft; grype will attempt dir:/" && SRC="dir:/"
    echo "[+] Running Grype against ${SRC}..."
    grype "$SRC" -o table | tee "$GRYPE_OUT" >/dev/null
    grype "$SRC" -o json > "$GRYPE_JSON" 2>/dev/null || true
    echo "[+] Grype reports saved: $GRYPE_OUT and $GRYPE_JSON"
  else
    echo "[-] grype not installed. Install with: curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"
  fi

  echo "=== Step 18: CVE Summary v3 — Grype backend ==="
  if [ -s "$GRYPE_JSON" ] && have_cmd jq; then
    TOTAL=$(jq '(.matches // []) | length' "$GRYPE_JSON")
    CRIT=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="critical")] | length' "$GRYPE_JSON")
    HIGH=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="high")] | length' "$GRYPE_JSON")
    MED=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="medium")] | length' "$GRYPE_JSON")
    LOW=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="low")] | length' "$GRYPE_JSON")
    NEGL=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="negligible")] | length' "$GRYPE_JSON")
    UNK=$(jq '[.matches[]? | .vulnerability.severity // empty | ascii_downcase | select(.=="unknown")] | length' "$GRYPE_JSON")
    U_TOTAL=$(jq -r '.matches[]? | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_CRIT=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="critical") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_HIGH=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="high") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_MED=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="medium") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_LOW=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="low") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_NEGL=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="negligible") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    U_UNK=$(jq -r '.matches[]? | select((.vulnerability.severity // "" | ascii_downcase)=="unknown") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    FIXED_RAW=$(jq '[.matches[]? | .vulnerability.fix.state // empty | ascii_downcase | select(.=="fixed")] | length' "$GRYPE_JSON")
    NOTFIX_RAW=$(jq '[.matches[]? | .vulnerability.fix.state // empty | ascii_downcase | select(.=="not-fixed" or .=="notfixed")] | length' "$GRYPE_JSON")
    WONT_RAW=$(jq '[.matches[]? | .vulnerability.fix.state // empty | ascii_downcase | select(.=="wont-fix" or .=="will-not-fix" or .=="deferred")] | length' "$GRYPE_JSON")
    UNKNOWN_FIX_RAW=$(jq '[.matches[]? | select((.vulnerability.fix.state // "") == "")] | length' "$GRYPE_JSON")
    FIXED_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "" | ascii_downcase)=="fixed") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    NOTFIX_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "" | ascii_downcase)=="notfixed") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    WONT_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "" | ascii_downcase)=="wont-fix" or (.vulnerability.fix.state // "" | ascii_downcase)=="will-not-fix" or (.vulnerability.fix.state // "" | ascii_downcase)=="deferred") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    UNKNOWN_FIX_UNIQ=$(jq -r '.matches[]? | select((.vulnerability.fix.state // "") == "") | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    # Cross-distro OS/package-domain classification v3.2:
    # - OS package: native package-manager artifacts or distro-match.
    # - Kernel/CPE: linux-kernel artifacts, reported separately because CPE matches can fan out heavily.
    # - Language/other: everything else.
    # Devuan/Debian kernel CVEs may appear as artifact.type="linux-kernel" with match type "cpe-match".
    OS_FILTER='(.artifact.type == "rpm" or .artifact.type == "deb" or .artifact.type == "dpkg" or .artifact.type == "apk" or .artifact.type == "alpm" or ([.matchDetails[]?.type] | any(. == "distro-match")))' 
    KERNEL_FILTER='(.artifact.type == "linux-kernel")' 
    OS_OR_KERNEL_FILTER="($OS_FILTER or $KERNEL_FILTER)"
    DIRECT_FILTER='([.matchDetails[]?.type] | any(. == "exact-direct-match" or . == "distro-match" or . == "exact-cpe-match" or . == "cpe-match"))' 

    OS_RAW=$(jq "[.matches[]? | select($OS_FILTER)] | length" "$GRYPE_JSON")
    OS_UNIQ=$(jq -r ".matches[]? | select($OS_FILTER) | .vulnerability.id" "$GRYPE_JSON" | sort -u | wc -l)
    KERNEL_RAW=$(jq "[.matches[]? | select($KERNEL_FILTER)] | length" "$GRYPE_JSON")
    KERNEL_UNIQ=$(jq -r ".matches[]? | select($KERNEL_FILTER) | .vulnerability.id" "$GRYPE_JSON" | sort -u | wc -l)
    LANG_RAW=$(jq "[.matches[]? | select(($OS_FILTER or $KERNEL_FILTER) | not)] | length" "$GRYPE_JSON")
    LANG_UNIQ=$(jq -r ".matches[]? | select(($OS_FILTER or $KERNEL_FILTER) | not) | .vulnerability.id" "$GRYPE_JSON" | sort -u | wc -l)
    DIRECT_RAW=$(jq "[.matches[]? | select($DIRECT_FILTER)] | length" "$GRYPE_JSON")
    DIRECT_UNIQ=$(jq -r ".matches[]? | select($DIRECT_FILTER) | .vulnerability.id" "$GRYPE_JSON" | sort -u | wc -l)
    UPSTREAM_RAW=$(jq '[.matches[]? | select([.matchDetails[]?.type] | any(test("upstream")))] | length' "$GRYPE_JSON")
    UPSTREAM_UNIQ=$(jq -r '.matches[]? | select([.matchDetails[]?.type] | any(test("upstream"))) | .vulnerability.id' "$GRYPE_JSON" | sort -u | wc -l)
    REAL_RAW=$(jq "[.matches[]? | select($OS_OR_KERNEL_FILTER) | select((.vulnerability.fix.state // \"\" | ascii_downcase)==\"not-fixed\" or (.vulnerability.fix.state // \"\" | ascii_downcase)==\"notfixed\") | select((.vulnerability.severity // \"\" | ascii_downcase)==\"critical\" or (.vulnerability.severity // \"\" | ascii_downcase)==\"high\") | select($DIRECT_FILTER)] | length" "$GRYPE_JSON")
    REAL_UNIQ=$(jq -r ".matches[]? | select($OS_OR_KERNEL_FILTER) | select((.vulnerability.fix.state // \"\" | ascii_downcase)==\"not-fixed\" or (.vulnerability.fix.state // \"\" | ascii_downcase)==\"notfixed\") | select((.vulnerability.severity // \"\" | ascii_downcase)==\"critical\" or (.vulnerability.severity // \"\" | ascii_downcase)==\"high\") | select($DIRECT_FILTER) | .vulnerability.id" "$GRYPE_JSON" | sort -u | wc -l)

    {
      echo "CYVS v3 Summary"; echo "==============="; echo "Timestamp:       $TS"; echo "Scanner backend: Grype/Syft"; echo "Atomic distro:   no"; echo "OS:              $OS_NAME"; echo "OS ID:           $OS_ID"; echo "OS Version:      $OS_VERSION"; echo "Kernel:          $(uname -r)"; echo "Package DB:      $PKG_DB"; echo ""
      echo "Raw Grype Matches"; echo "-----------------"; printf "Total raw matches:       %s\n" "$TOTAL"; printf "Critical raw matches:    %s\n" "$CRIT"; printf "High raw matches:        %s\n" "$HIGH"; printf "Medium raw matches:      %s\n" "$MED"; printf "Low raw matches:         %s\n" "$LOW"; printf "Negligible raw matches:  %s\n" "$NEGL"; printf "Unknown raw matches:     %s\n" "$UNK"; echo ""
      echo "Unique CVEs"; echo "-----------"; printf "Unique total CVEs:       %s\n" "$U_TOTAL"; printf "Unique critical CVEs:    %s\n" "$U_CRIT"; printf "Unique high CVEs:        %s\n" "$U_HIGH"; printf "Unique medium CVEs:      %s\n" "$U_MED"; printf "Unique low CVEs:         %s\n" "$U_LOW"; printf "Unique negligible CVEs:  %s\n" "$U_NEGL"; printf "Unique unknown CVEs:     %s\n" "$U_UNK"; echo ""
      echo "Fix State"; echo "---------"; printf "Fixed raw / unique:      %s / %s\n" "$FIXED_RAW" "$FIXED_UNIQ"; printf "Not-fixed raw / unique:  %s / %s\n" "$NOTFIX_RAW" "$NOTFIX_UNIQ"; printf "Wont-fix raw / unique:   %s / %s\n" "$WONT_RAW" "$WONT_UNIQ"; printf "Unknown raw / unique:    %s / %s\n" "$UNKNOWN_FIX_RAW" "$UNKNOWN_FIX_UNIQ"; echo ""
      echo "Package Domain"; echo "--------------"; printf "OS package raw / unique:       %s / %s\n" "$OS_RAW" "$OS_UNIQ"; printf "Kernel/CPE raw / unique:       %s / %s\n" "$KERNEL_RAW" "$KERNEL_UNIQ"; printf "Language/other raw / unique:   %s / %s\n" "$LANG_RAW" "$LANG_UNIQ"; echo ""
      echo "Match Quality"; echo "-------------"; printf "Direct/distro/exact raw / unique:    %s / %s\n" "$DIRECT_RAW" "$DIRECT_UNIQ"; printf "Upstream-related raw / unique:       %s / %s\n" "$UPSTREAM_RAW" "$UPSTREAM_UNIQ"; echo ""
      echo "Real Risk v3 Conservative Distro Metric"; echo "---------------------------------------"; echo "Definition: OS package OR linux-kernel + not-fixed + critical/high + direct/distro/exact-cpe/cpe match"; printf "Real-risk raw matches:   %s\n" "$REAL_RAW"; printf "Real-risk unique CVEs:   %s\n" "$REAL_UNIQ"; echo ""
      echo "Generated Files"; echo "---------------"; echo "Versions:        $VERSIONS_FILE"; echo "Package list:    $PKG_LIST"; echo "Syft JSON:       $SBOM_JSON"; echo "Syft CycloneDX:  $SBOM_CDX"; echo "Grype table:     $GRYPE_OUT"; echo "Grype JSON:      $GRYPE_JSON"; echo "Summary text:    $SUMMARY_TXT"; echo "Summary JSON:    $SUMMARY_JSON"; echo "Fan-out table:   $FANOUT_TXT"; echo "Real-risk CSV:   $REAL_RISK_CSV"
    } | tee "$SUMMARY_TXT"

    jq -n --arg timestamp "$TS" --arg scanner "grype" --arg os "$OS_NAME" --arg os_id "$OS_ID" --arg os_version "$OS_VERSION" --arg kernel "$(uname -r)" --argjson total "$TOTAL" --argjson unique_total "$U_TOTAL" --argjson unique_critical "$U_CRIT" --argjson unique_high "$U_HIGH" --argjson fixed_unique "$FIXED_UNIQ" --argjson notfixed_unique "$NOTFIX_UNIQ" --argjson unknown_fix_unique "$UNKNOWN_FIX_UNIQ" --argjson os_unique "$OS_UNIQ" --argjson kernel_unique "$KERNEL_UNIQ" --argjson language_unique "$LANG_UNIQ" --argjson real_risk_unique "$REAL_UNIQ" '{timestamp:$timestamp,scanner_backend:$scanner,os:$os,os_id:$os_id,os_version:$os_version,kernel:$kernel,raw_matches:$total,unique_total_cves:$unique_total,unique_critical_cves:$unique_critical,unique_high_cves:$unique_high,fixed_unique_cves:$fixed_unique,notfixed_unique_cves:$notfixed_unique,unknown_fix_unique_cves:$unknown_fix_unique,os_package_unique_cves:$os_unique,kernel_cpe_unique_cves:$kernel_unique,language_other_unique_cves:$language_unique,real_risk_unique_cves:$real_risk_unique}' > "$SUMMARY_JSON"
    jq -r '.matches[]? | [.vulnerability.id, (.vulnerability.severity // "unknown"), (.vulnerability.fix.state // "unknown")] | @tsv' "$GRYPE_JSON" | sort | uniq -c | sort -nr | head -20 > "$FANOUT_TXT"
    jq -r '["cve","severity","fix_state","package","version","type","match_types"], (.matches[]? | select((.artifact.type == "rpm" or .artifact.type == "deb" or .artifact.type == "dpkg" or .artifact.type == "apk" or .artifact.type == "alpm" or .artifact.type == "linux-kernel") or ([.matchDetails[]?.type] | any(. == "distro-match"))) | select((.vulnerability.fix.state // "" | ascii_downcase)=="not-fixed" or (.vulnerability.fix.state // "" | ascii_downcase)=="notfixed") | select((.vulnerability.severity // "" | ascii_downcase)=="critical" or (.vulnerability.severity // "" | ascii_downcase)=="high") | select([.matchDetails[]?.type] | any(. == "exact-direct-match" or . == "distro-match" or . == "exact-cpe-match" or . == "cpe-match")) | [.vulnerability.id, (.vulnerability.severity // "unknown"), (.vulnerability.fix.state // "unknown"), (.artifact.name // "unknown"), (.artifact.version // "unknown"), (.artifact.type // "unknown"), ([.matchDetails[]?.type] | unique | join("|"))]) | @csv' "$GRYPE_JSON" > "$REAL_RISK_CSV"
    echo "=== Top 20 CVE Fan-out Amplifiers ==="; cat "$FANOUT_TXT"
    echo "=== Real Risk v3 Preview ==="; head -n 20 "$REAL_RISK_CSV"
  else
    echo "[-] No Grype output to summarize, or jq is not installed."
  fi
fi

###############################################################################
# Trivy backend for atomic/OSTree distros
###############################################################################

if [ "$SCANNER" = "trivy" ]; then
  echo "=== Test 16: Software Inventory + SBOM ==="
  echo "[+] Atomic/OSTree mode: skipping Syft SBOM generation."
  echo "[+] Reason: Syft/Grype may create an oversized OSTree SBOM graph and OOM."
  echo "[+] Atomic interpretation model: Trivy ecosystem-aware risk, not OS-package-only risk."

  echo "=== Step 17: Vulnerability Scan (Trivy rootfs) ==="
  TRIVY_JSON="${OUTDIR}/trivy_report_${TS}.json"
  if have_cmd trivy; then
    echo "[+] Running Trivy rootfs scan. First run may download/update the Trivy DB."
    # Deliberately skip high-churn/cache areas. Do NOT skip /sysroot/ostree here because
    # that is where Fedora Atomic deployments live; v3.3 classifies those results instead.
    $SUDO trivy rootfs / \
      --scanners vuln \
      --format json \
      --output "$TRIVY_JSON" \
      --skip-dirs /proc,/sys,/dev,/run,/tmp,/var/tmp,/mnt,/media,/var/lib/containers,/var/lib/docker,/var/lib/flatpak,/home,/root/.cache \
      || true
    echo "[+] Trivy report saved: $TRIVY_JSON"
  else
    echo "[-] trivy not installed."
    echo "    Fedora often supports: sudo dnf install -y trivy"
    echo "    Otherwise use Aqua Security's official Trivy install instructions."
  fi

  echo "=== Step 18: CVE Summary v3.3 — Trivy atomic backend ==="
  if [ -s "$TRIVY_JSON" ] && have_cmd jq; then
    TOTAL=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$TRIVY_JSON")
    CRIT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$TRIVY_JSON")
    HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$TRIVY_JSON")
    MED=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "$TRIVY_JSON")
    LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "$TRIVY_JSON")
    UNK=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="UNKNOWN" or .Severity==null)] | length' "$TRIVY_JSON")

    U_TOTAL=$(jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    U_CRIT=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    U_HIGH=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH") | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    U_MED=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM") | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    U_LOW=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW") | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    U_UNK=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="UNKNOWN" or .Severity==null) | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)

    FIXED_RAW=$(jq '[.Results[]?.Vulnerabilities[]? | select((.FixedVersion // "") != "" or .Status=="fixed")] | length' "$TRIVY_JSON")
    AFFECTED_RAW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))] | length' "$TRIVY_JSON")
    FIXED_UNIQ=$(jq -r '.Results[]?.Vulnerabilities[]? | select((.FixedVersion // "") != "" or .Status=="fixed") | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    AFFECTED_UNIQ=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed")) | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)

    # Trivy Result.Type values differ from Grype artifact.type values.  Atomic Fedora often
    # reports python-pkg, conda-pkg, node-pkg, gobinary, cargo, etc. rather than fedora/rpm.
    OS_RAW=$(jq '[.Results[]? | select(.Type=="fedora" or .Type=="redhat" or .Type=="debian" or .Type=="ubuntu" or .Type=="alpine" or .Type=="photon" or .Type=="rpm") | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    OS_UNIQ=$(jq -r '.Results[]? | select(.Type=="fedora" or .Type=="redhat" or .Type=="debian" or .Type=="ubuntu" or .Type=="alpine" or .Type=="photon" or .Type=="rpm") | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    LANG_RAW=$(jq '[.Results[]? | select(.Type=="python-pkg" or .Type=="node-pkg" or .Type=="conda-pkg" or .Type=="cargo" or .Type=="composer" or .Type=="jar" or .Type=="npm" or .Type=="pip" or .Type=="gem" or .Type=="rubygems" or .Type=="gomod") | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    LANG_UNIQ=$(jq -r '.Results[]? | select(.Type=="python-pkg" or .Type=="node-pkg" or .Type=="conda-pkg" or .Type=="cargo" or .Type=="composer" or .Type=="jar" or .Type=="npm" or .Type=="pip" or .Type=="gem" or .Type=="rubygems" or .Type=="gomod") | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    GOBIN_RAW=$(jq '[.Results[]? | select(.Type=="gobinary") | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    GOBIN_UNIQ=$(jq -r '.Results[]? | select(.Type=="gobinary") | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)

    OSTREE_DEPLOY_RAW=$(jq '[.Results[]? | select((.Target // "") | test("(^|/)sysroot/ostree/deploy/")) | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    OSTREE_DEPLOY_UNIQ=$(jq -r '.Results[]? | select((.Target // "") | test("(^|/)sysroot/ostree/deploy/")) | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    OSTREE_REPO_RAW=$(jq '[.Results[]? | select((.Target // "") | test("(^|/)sysroot/ostree/repo/")) | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    OSTREE_REPO_UNIQ=$(jq -r '.Results[]? | select((.Target // "") | test("(^|/)sysroot/ostree/repo/")) | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    USER_RAW=$(jq '[.Results[]? | select((.Target // "") | test("(^|/)var/home/|(^|/)home/|(^|/)var/usrlocal/|(^|/)usr/local/")) | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    USER_UNIQ=$(jq -r '.Results[]? | select((.Target // "") | test("(^|/)var/home/|(^|/)home/|(^|/)var/usrlocal/|(^|/)usr/local/")) | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    CONTAINER_RAW=$(jq '[.Results[]? | select((.Target // "") | test("containers/storage|var/lib/containers|var/home/.*/\\.local/share/containers")) | .Vulnerabilities[]?] | length' "$TRIVY_JSON")
    CONTAINER_UNIQ=$(jq -r '.Results[]? | select((.Target // "") | test("containers/storage|var/lib/containers|var/home/.*/\\.local/share/containers")) | .Vulnerabilities[]?.VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)

    # v3.3 Atomic real-risk model:
    # On OSTree systems, Trivy may not expose the immutable base as normal Fedora/RPM OS packages.
    # Therefore real risk is derived from Trivy's vulnerability state directly.
    ATOMIC_REAL_RAW=$(jq '[.Results[]?.Vulnerabilities[]?
      | select(.Severity=="CRITICAL" or .Severity=="HIGH")
      | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))
    ] | length' "$TRIVY_JSON")
    ATOMIC_REAL_UNIQ=$(jq -r '.Results[]?.Vulnerabilities[]?
      | select(.Severity=="CRITICAL" or .Severity=="HIGH")
      | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))
      | .VulnerabilityID' "$TRIVY_JSON" | sort -u | wc -l)
    ATOMIC_REAL_PKGS=$(jq -r '.Results[]?.Vulnerabilities[]?
      | select(.Severity=="CRITICAL" or .Severity=="HIGH")
      | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))
      | .PkgName' "$TRIVY_JSON" | sort -u | wc -l)

    {
      echo "CYVS v3.3 Summary"; echo "================="; echo "Timestamp:       $TS"; echo "Scanner backend: Trivy rootfs"; echo "Atomic distro:   yes"; echo "Atomic reason:   $ATOMIC_REASON"; echo "OS:              $OS_NAME"; echo "OS ID:           $OS_ID"; echo "OS Version:      $OS_VERSION"; echo "Kernel:          $(uname -r)"; echo "Package DB:      $PKG_DB"; echo ""
      echo "Raw Trivy Matches"; echo "-----------------"; printf "Total raw matches:       %s\n" "$TOTAL"; printf "Critical raw matches:    %s\n" "$CRIT"; printf "High raw matches:        %s\n" "$HIGH"; printf "Medium raw matches:      %s\n" "$MED"; printf "Low raw matches:         %s\n" "$LOW"; printf "Unknown raw matches:     %s\n" "$UNK"; echo ""
      echo "Unique CVEs"; echo "-----------"; printf "Unique total CVEs:       %s\n" "$U_TOTAL"; printf "Unique critical CVEs:    %s\n" "$U_CRIT"; printf "Unique high CVEs:        %s\n" "$U_HIGH"; printf "Unique medium CVEs:      %s\n" "$U_MED"; printf "Unique low CVEs:         %s\n" "$U_LOW"; printf "Unique unknown CVEs:     %s\n" "$U_UNK"; echo ""
      echo "Fix State"; echo "---------"; printf "Fixed raw / unique:      %s / %s\n" "$FIXED_RAW" "$FIXED_UNIQ"; printf "Affected/no-fix raw / unique: %s / %s\n" "$AFFECTED_RAW" "$AFFECTED_UNIQ"; echo ""
      echo "Atomic Package / Location Buckets"; echo "---------------------------------"; printf "OS package raw / unique:        %s / %s\n" "$OS_RAW" "$OS_UNIQ"; printf "Language pkg raw / unique:      %s / %s\n" "$LANG_RAW" "$LANG_UNIQ"; printf "Go binary raw / unique:         %s / %s\n" "$GOBIN_RAW" "$GOBIN_UNIQ"; printf "OSTree deploy raw / unique:     %s / %s\n" "$OSTREE_DEPLOY_RAW" "$OSTREE_DEPLOY_UNIQ"; printf "OSTree repo raw / unique:       %s / %s\n" "$OSTREE_REPO_RAW" "$OSTREE_REPO_UNIQ"; printf "User/local raw / unique:        %s / %s\n" "$USER_RAW" "$USER_UNIQ"; printf "Container storage raw / unique: %s / %s\n" "$CONTAINER_RAW" "$CONTAINER_UNIQ"; echo ""
      echo "Real Risk v3.3 Atomic Metric"; echo "----------------------------"; echo "Definition: critical/high + affected/no fixed version across Trivy ecosystems"; printf "Atomic real-risk raw matches:      %s\n" "$ATOMIC_REAL_RAW"; printf "Atomic real-risk unique CVEs:      %s\n" "$ATOMIC_REAL_UNIQ"; printf "Atomic real-risk unique packages:  %s\n" "$ATOMIC_REAL_PKGS"; echo ""
      echo "Generated Files"; echo "---------------"; echo "Versions:        $VERSIONS_FILE"; echo "Package list:    $PKG_LIST"; echo "Trivy JSON:      $TRIVY_JSON"; echo "Summary text:    $SUMMARY_TXT"; echo "Summary JSON:    $SUMMARY_JSON"; echo "Fan-out table:   $FANOUT_TXT"; echo "Real-risk CSV:   $REAL_RISK_CSV"
    } | tee "$SUMMARY_TXT"

    jq -n \
      --arg timestamp "$TS" \
      --arg scanner "trivy" \
      --arg atomic_reason "$ATOMIC_REASON" \
      --arg os "$OS_NAME" \
      --arg os_id "$OS_ID" \
      --arg os_version "$OS_VERSION" \
      --arg kernel "$(uname -r)" \
      --argjson total "$TOTAL" \
      --argjson unique_total "$U_TOTAL" \
      --argjson unique_critical "$U_CRIT" \
      --argjson unique_high "$U_HIGH" \
      --argjson fixed_unique "$FIXED_UNIQ" \
      --argjson affected_unique "$AFFECTED_UNIQ" \
      --argjson os_unique "$OS_UNIQ" \
      --argjson language_unique "$LANG_UNIQ" \
      --argjson gobinary_unique "$GOBIN_UNIQ" \
      --argjson ostree_deploy_unique "$OSTREE_DEPLOY_UNIQ" \
      --argjson ostree_repo_unique "$OSTREE_REPO_UNIQ" \
      --argjson user_local_unique "$USER_UNIQ" \
      --argjson container_unique "$CONTAINER_UNIQ" \
      --argjson atomic_real_risk_unique "$ATOMIC_REAL_UNIQ" \
      --argjson atomic_real_risk_packages "$ATOMIC_REAL_PKGS" \
      '{timestamp:$timestamp,scanner_backend:$scanner,atomic_reason:$atomic_reason,os:$os,os_id:$os_id,os_version:$os_version,kernel:$kernel,raw_matches:$total,unique_total_cves:$unique_total,unique_critical_cves:$unique_critical,unique_high_cves:$unique_high,fixed_unique_cves:$fixed_unique,affected_no_fix_unique_cves:$affected_unique,os_package_unique_cves:$os_unique,language_package_unique_cves:$language_unique,gobinary_unique_cves:$gobinary_unique,ostree_deploy_unique_cves:$ostree_deploy_unique,ostree_repo_unique_cves:$ostree_repo_unique,user_local_unique_cves:$user_local_unique,container_storage_unique_cves:$container_unique,atomic_real_risk_unique_cves:$atomic_real_risk_unique,atomic_real_risk_unique_packages:$atomic_real_risk_packages}' > "$SUMMARY_JSON"

    jq -r '.Results[]?.Vulnerabilities[]? | [.VulnerabilityID, (.Severity // "UNKNOWN"), (if (.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed")) then "affected/no-fix" else "fixed" end)] | @tsv' "$TRIVY_JSON" | sort | uniq -c | sort -nr | head -20 > "$FANOUT_TXT"

    jq -r '
      ["cve","severity","status","package","installed_version","fixed_version","target","type","purl"],
      (.Results[]? as $r
        | .Vulnerabilities[]?
        | select(.Severity=="CRITICAL" or .Severity=="HIGH")
        | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))
        | [
            .VulnerabilityID,
            (.Severity // "UNKNOWN"),
            (.Status // "unknown"),
            (.PkgName // "unknown"),
            (.InstalledVersion // "unknown"),
            (.FixedVersion // ""),
            ($r.Target // "unknown"),
            ($r.Type // "unknown"),
            (.PkgIdentifier.PURL // "")
          ]
      )
      | @csv
    ' "$TRIVY_JSON" > "$REAL_RISK_CSV"

    ATOMIC_REAL_PKGS_TXT="${OUTDIR}/cyvs_v3_atomic_real_risk_packages_${TS}.txt"
    jq -r '
      .Results[]?.Vulnerabilities[]?
      | select(.Severity=="CRITICAL" or .Severity=="HIGH")
      | select(.Status=="affected" or ((.FixedVersion // "") == "" and (.Status // "") != "fixed"))
      | [.VulnerabilityID, .PkgName, .Severity, (.Status // "unknown")]
      | @tsv
    ' "$TRIVY_JSON" | sort -u > "$ATOMIC_REAL_PKGS_TXT"

    echo "=== Top 20 CVE Fan-out Amplifiers ==="; cat "$FANOUT_TXT"
    echo "=== Atomic Real Risk v3.3 Preview ==="; head -n 20 "$REAL_RISK_CSV"
    echo "=== Atomic Real Risk Unique CVEs/Packages ==="; cat "$ATOMIC_REAL_PKGS_TXT"
  else
    echo "[-] No Trivy output to summarize, or jq is not installed."
  fi
fi

echo ""
echo "[+] CYVS v3 complete."
echo "[+] Main summary:    $SUMMARY_TXT"
echo "[+] Machine summary: $SUMMARY_JSON"
echo "[+] Scanner backend: $SCANNER"
