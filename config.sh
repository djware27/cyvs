#!/usr/bin/env bash
# cyvs-configure.sh — Preflight for cyvs.sh (no installs; diagnostics only)
# Works on: Debian, Devuan, Arch, Fedora, openSUSE/Tumbleweed (others labeled "unknown")
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
  debian|devuan)                 PKG_MGR="apt"    ;;
  fedora)                        PKG_MGR="dnf"    ;;
  arch)                          PKG_MGR="pacman" ;;
  opensuse*|suse|tumbleweed|sle) PKG_MGR="zypper" ;;
  *)                             PKG_MGR="unknown";;
esac

bold "cyvs-configure.sh — Preflight for cyvs.sh"
rule
info "Detected OS: ${OS_ID}"
info "Package manager: ${PKG_MGR}"
rule

need_cmds=( "bash" "grep" "mount" "cat" "awk" "sed" "date" )
kernel_cmds=( "dmesg" )
systemd_cmds=( "systemctl" "systemd-analyze" "journalctl" )
cve_cmds=( "grype" "syft" )

have() { command -v "$1" >/dev/null 2>&1; }

# Detect if PID 1 is NOT systemd (Devuan, Alpine, containers, etc.)
is_non_systemd_init() {
  local init; init="$(ps -p 1 -o comm= 2>/dev/null || true)"
  [ -n "$init" ] && [ "$init" != "systemd" ]
}

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
  local missing=("$@")
  if [ "$PKG_MGR" = "unknown" ]; then
    warn "Cannot suggest install commands for unknown package manager."
    return 0
  fi

  # Strip systemd tools from suggestions if PID 1 isn't systemd
  if is_non_systemd_init; then
    local filtered=()
    for m in "${missing[@]}"; do
      case "$m" in
        systemctl|systemd-analyze|journalctl) continue ;;
      esac
      filtered+=("$m")
    done
    missing=("${filtered[@]}")
  fi

  info "Suggested install commands (review before use):"
  case "$PKG_MGR" in
    apt)
      echo "  sudo apt update"
      echo "  sudo apt install -y coreutils util-linux grep procps ${missing[*]//grype/} ${missing[*]//syft/}"
      ;;
    dnf)
      echo "  sudo dnf install -y coreutils util-linux grep procps-ng ${missing[*]//grype/} ${missing[*]//syft/}"
      ;;
    pacman)
      echo "  sudo pacman -Syu coreutils util-linux grep procps-ng ${missing[*]//grype/} ${missing[*]//syft/}"
      ;;
    zypper)
      echo "  sudo zypper refresh"
      echo "  sudo zypper install -y coreutils util-linux grep procps ${missing[*]//grype/} ${missing[*]//syft/}"
      ;;
  esac

  # Upstream installers for grype/syft (commonly installed via curl script)
  if printf "%s\n" "${missing[@]}" | grep -q '^grype$'; then
    echo "  # Grype (recommended for CVE summaries):"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
  fi
  if printf "%s\n" "${missing[@]}" | grep -q '^syft$'; then
    echo "  # Syft (optional, SBOM accuracy):"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
  fi
}

# --- Version helpers (prints "version (gitcommit)" when available) ---
tool_version_extended() {
  # usage: tool_version_extended grype|syft
  "$1" version 2>/dev/null | awk -F': *' '
    /^[[:space:]]*Version/   {ver=$2}
    /^[[:space:]]*GitCommit/ {gc=$2}
    END{
      if (ver && gc) printf "%s (%s)\n", ver, gc;
      else if (ver)  print ver;
    }'
}

bold "1) Base command availability"
check_cmds "Base utils" "${need_cmds[@]}"

bold "2) Kernel visibility commands"
check_cmds "Kernel interfaces" "${kernel_cmds[@]}"

bold "3) systemd-related commands"
INIT_CMD="$(ps -p 1 -o comm= 2>/dev/null || true)"
if [ -n "$INIT_CMD" ] && [ "$INIT_CMD" != "systemd" ]; then
  for c in "${systemd_cmds[@]}"; do
    printf "  - %-16s SKIP\n" "$c"
  done
  info "Non-systemd init detected (PID 1: ${INIT_CMD}); skipping systemd-specific tooling."
else
  check_cmds "systemd tools" "${systemd_cmds[@]}"
fi

bold "4) CVE tooling"
check_cmds "Vulnerability tools" "${cve_cmds[@]}"

# Show concise versions for grype/syft
if have grype; then
  v="$(tool_version_extended grype)"; [ -n "${v:-}" ] && info "grype: ${v}" || info "grype: (version unavailable)"
fi
if have syft; then
  v="$(tool_version_extended syft)";  [ -n "${v:-}" ] && info "syft:  ${v}" || info "syft: (version unavailable)"
fi

rule
bold "Environment checks"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  warn "Not running as root. Some checks in cyvs.sh may show partial data."
else
  info "Running as root: full access for read-only checks is available."
fi

CG_LINE="$(mount | grep -E ' /sys/fs/cgroup ' || true)"
if echo "$CG_LINE" | grep -q 'type cgroup2'; then
  info "cgroup: v2 detected."
else
  if [ -n "$CG_LINE" ]; then
    warn "cgroup: legacy (v1) or mixed mode detected."
  else
    warn "cgroup mount not found; container/minimal images may differ."
  fi
fi

if ls /sys/devices/system/cpu/vulnerabilities/* >/dev/null 2>&1; then
  info "Mitigation interfaces present under /sys/devices/system/cpu/vulnerabilities/"
else
  warn "Mitigation interfaces not found."
fi

if [ -r /proc/cmdline ]; then
  info "/proc/cmdline is readable."
else
  warn "/proc/cmdline not readable; bootline checks may fail."
fi

if [ -n "$INIT_CMD" ] && [ "$INIT_CMD" != "systemd" ]; then
  warn "systemd not detected; cyvs.sh will SKIP boot timing checks and journal queries."
else
  if systemctl is-system-running >/dev/null 2>&1; then
    info "systemd appears active; systemd-analyze should work."
  else
    warn "systemd command exists but not active in this context."
  fi
fi

rule
bold "Predicted cyvs.sh test outcomes"

predict() { printf "  - %-32s %s\n" "$1" "$2"; }

if echo "$CG_LINE" | grep -q 'type cgroup2'; then
  predict "Cgroup v2 verification" "PASS"
else
  predict "Cgroup v2 verification" "LIKELY-FAIL"
fi

if ls /sys/devices/system/cpu/vulnerabilities/* >/dev/null 2>&1; then
  predict "Spectre/Meltdown status" "PASS"
else
  predict "Spectre/Meltdown status" "LIKELY-FAIL"
fi

if [ -r /proc/cmdline ]; then
  predict "Bootline safety (cmdline)" "PASS"
else
  predict "Bootline safety (cmdline)" "FAIL"
fi

if [ -n "$INIT_CMD" ] && [ "$INIT_CMD" != "systemd" ]; then
  predict "Boot performance (systemd-analyze)" "SKIP (no systemd)"
  predict "Journal error scan" "SKIP (no systemd/journal)"
else
  predict "Boot performance (systemd-analyze)" "PASS"
  predict "Journal error scan" "PASS"
fi

if have grype; then
  predict "CVE summary (Grype)" "PASS"
else
  predict "CVE summary (Grype)" "SKIP (grype not installed)"
fi

if have syft; then
  predict "SBOM inventory (Syft)" "PASS"
else
  predict "SBOM inventory (Syft)" "SKIP (syft not installed)"
fi

rule
bold "Notes"
cat <<'EOF'
- This preflight makes no changes to your system.
- Use the suggested install commands only if you choose to enable skipped checks.
- For Devuan or other non-systemd setups, cyvs.sh will automatically skip systemd-specific steps.
- For the most accurate CVE results, install grype (and optionally syft) and run cyvs.sh as root.
- Snapshots (Btrfs/overlay) are restore points; tar/rsync-style backups are equally valid for point-in-time capture.
EOF
rule
info "Preflight complete."
