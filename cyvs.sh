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
rpm -q --changelog kernel | grep -i cve | head -n 20

echo "=== Test 6: Security Tools Audit ==="
rpm -qa | grep -i selinux
rpm -qa | grep audit

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

if command -v cvechecker >/dev/null 2>&1; then
    echo "[+] Initializing CVE database..."
    sudo cvechecker --initdbs >/dev/null 2>&1

    echo "[+] Generating binary list..."
    BINLIST_FILE="./cve_binlist.txt"
    find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null > "$BINLIST_FILE"

    echo "[+] Running CVE check against binaries..."
    sudo cvechecker --runcheck --fileinfo="$BINLIST_FILE" --csvoutput > cve_report.csv

    if [[ -s cve_report.csv ]]; then
        echo "[+] CVE report saved to cve_report.csv"
        echo "[+] Showing top 10 entries:"
        head -n 10 cve_report.csv
    else
        echo "[-] CVE report came back empty. It may not recognize the distro's package versions."
    fi
else
    echo "[-] cvechecker not installed. Skipping test."
    echo "    Install with: sudo dnf install cve-check-tool"
fi

echo "=== Test 16: Full CVE Vulnerability Scan (grype) ==="

# Check if grype is installed
if ! command -v grype >/dev/null 2>&1; then
    echo "[-] Grype not found. Please install it from https://github.com/anchore/grype"
else
    timestamp=$(date +%Y%m%d_%H%M%S)
    report_file="grype_report_${timestamp}.txt"

    echo "[+] Running grype scan on / (this may take a while)..."
    grype -o table dir:/ --file "$report_file" > /dev/null 2>&1

    if [ -f "$report_file" ]; then
        echo "[+] Report saved to: $report_file"

	critical=$(grep -cw 'Critical' "$report_file")
	high=$(grep -cw 'High' "$report_file")
	medium=$(grep -cw 'Medium' "$report_file")
	low=$(grep -cw 'Low' "$report_file")
	negligible=$(grep -cw 'Negligible' "$report_file")
	unknown=$(grep -cw 'Unknown' "$report_file")

        echo "Summary:"
        echo "  Critical:    $critical"
        echo "  High:        $high"
        echo "  Medium:      $medium"
        echo "  Low:         $low"
        echo "  Negligible:  $negligible"
        echo "  Unknown:     $unknown"
    else
        echo "[-] Report not found. Grype scan may have failed."
    fi
fi
