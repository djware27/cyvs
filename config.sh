#!/usr/bin/env bash
# cyvs-configure.sh — Preflight for cyvs.sh (no installs; diagnostics only)
# Purpose: Detect distro, verify prerequisites, and predict which cyvs.sh checks will pass/skip/fail.
# Works on: Debian, Devuan, Arch, Fedora (others will be labeled "unknown")
# License: MIT

set -euo pipefail

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
info() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*"; }
err()  { printf "[ERR ] %s\n" "$*" >&2; }
rule() { printf "%s\n" "----------------------------------------"; }

OS_ID="unknown"; PKG_MGR="unknown"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
fi

case "$OS_ID" in
  debian|devuan) PKG_MGR="apt";;
  fedora)        PKG_MGR="dnf";;
  arch)          PKG_MGR="pacman";;
  *)             PKG_MGR="unknown";;
esac

bold "cyvs-configure.sh — Preflight for cyvs.sh"
rule
info "Detected OS: ${OS_ID}"
info "Package manager: ${PKG_MGR}"
rule

need_cmds=( "bash" "grep" "mount" "cat" "awk" "sed" "date" )
kernel_cmds=( "dmesg" )
systemd_cmds=( "systemctl" "systemd-analyze" "journalctl" )
cve_cmds=( "grype" )   # syft is optional but improves accuracy

have() { command -v "$1" >/dev/null 2>&1; }
check_cmds() {
  local label="$1"; shift
  local missing=()
  for c in "$@"; do
    if have "$c"; then
      printf "  - %-16s OK\n" "$c"
    else
      printf "  - %-16s MISSING\n" "$c"
      missing+=("$c")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "$label: missing ${#missing[@]} command(s)."
    suggest_installs "${missing[@]}"
  else
    info "$label: all commands present."
  fi
}

suggest_installs() {
  # Best-effort hints; nothing is installed automatically.
  local missing=("$@")
  if [ "$PKG_MGR" = "unknown" ]; then
    warn "Cannot suggest install commands for unknown package manager."
    return 0
  fi

  info "Suggested install commands (review before use):"
  case "$PKG_MGR" in
    apt)
      # Map procps/procps-ng differences implicitly covered by 'procps'
      echo "  sudo apt update"
      echo "  sudo apt install -y coreutils util-linux grep procps systemd ${missing[*]//grype/}";;
    dnf)
      echo "  sudo dnf install -y coreutils util-linux grep procps-ng systemd ${missing[*]//grype/}";;
    pacman)
      echo "  sudo pacman -Syu coreutils util-linux grep procps-ng systemd ${missing[*]//grype/}";;
  esac

  # Separate note for grype/syft (often installed via upstream script)
  if printf "%s\n" "${missing[@]}" | grep -q '^grype$'; then
    echo "  # Grype (recommended for CVE summaries):"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
  fi
  if printf "%s\n" "${missing[@]}" | grep -q '^syft$'; then
    echo "  # Syft (optional, SBOM accuracy):"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
  fi
}

bold "1) Base command availability"
check_cmds "Base utils" "${need_cmds[@]}"

bold "2) Kernel visibility commands"
check_cmds "Kernel interfaces" "${kernel_cmds[@]}"

bold "3) systemd-related commands"
check_cmds "systemd tools" "${systemd_cmds[@]}"

bold "4) CVE tooling"
check_cmds "Vulnerability tools" "${cve_cmds[@]}"

rule
bold "Environment checks"

# Check sudo/root (read-only, but some paths require elevated perms for consistent results)
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  warn "Not running as root. Some checks in cyvs.sh may show partial data. Recommended: run with sudo."
else
  info "Running as root: full access for read-only checks is available."
fi

# Check cgroup mount type
CG_LINE="$(mount | grep -E ' /sys/fs/cgroup ' || true)"
if echo "$CG_LINE" | grep -q 'type cgroup2'; then
  info "cgroup: v2 detected."
else
  if [ -n "$CG_LINE" ]; then
    warn "cgroup: legacy (v1) detected or mixed. cyvs.sh will flag this."
  else
    warn "cgroup mount not found; container/minimal images may differ. cyvs.sh will report what it sees."
  fi
fi

# Check kernel mitigation files presence
if ls /sys/devices/system/cpu/vulnerabilities/* >/dev/null 2>&1; then
  info "Mitigation interfaces present under /sys/devices/system/cpu/vulnerabilities/"
else
  warn "Mitigation interfaces not found. Very old kernels or restricted containers may lack these."
fi

# Check /proc/cmdline readable
if [ -r /proc/cmdline ]; then
  info "/proc/cmdline is readable."
else
  warn "/proc/cmdline is not readable; bootline checks will likely fail."
fi

# systemd presence (Devuan may not use systemd)
if have systemctl; then
  if systemctl is-system-running >/dev/null 2>&1; then
    info "systemd appears active; systemd-analyze should work."
  else
    warn "systemd command exists but not active in this context."
  fi
else
  warn "systemd not detected; cyvs.sh will SKIP boot timing checks and journal queries."
fi

# Predict outcomes
rule
bold "Predicted cyvs.sh test outcomes"

predict() { printf "  - %-32s %s\n" "$1" "$2"; }

# Cgroup check
if echo "$CG_LINE" | grep -q 'type cgroup2'; then
  predict "Cgroup v2 verification" "PASS"
else
  predict "Cgroup v2 verification" "LIKELY-FAIL (legacy or missing)"
fi

# Mitigations files
if ls /sys/devices/system/cpu/vulnerabilities/* >/dev/null 2>&1; then
  predict "Spectre/Meltdown status" "PASS"
else
  predict "Spectre/Meltdown status" "LIKELY-FAIL (no interfaces)"
fi

# Bootline
if [ -r /proc/cmdline ]; then
  predict "Bootline safety (cmdline)" "PASS"
else
  predict "Bootline safety (cmdline)" "LIKELY-FAIL (not readable)"
fi

# systemd analyze
if have systemd-analyze && have systemctl && systemctl is-system-running >/dev/null 2>&1; then
  predict "Boot performance (systemd-analyze)" "PASS"
else
  predict "Boot performance (systemd-analyze)" "SKIP (no systemd)"
fi

# journal errors
if have journalctl && have systemctl && systemctl is-system-running >/dev/null 2>&1; then
  predict "Journal error scan" "PASS"
else
  predict "Journal error scan" "SKIP (no systemd/journal)"
fi

# CVE summary
if have grype; then
  predict "CVE summary (Grype)" "PASS"
else
  predict "CVE summary (Grype)" "SKIP (grype not installed)"
fi

rule
bold "Notes"
cat <<'EOF'
- This preflight makes no changes to your system.
- Use the suggested install commands only if you choose to enable skipped checks.
- For Devuan or other non-systemd setups, cyvs.sh will automatically skip systemd-specific steps.
- For the most accurate CVE results, install grype (and optionally syft) and run cyvs.sh as root.
EOF
rule
info "Preflight complete."
