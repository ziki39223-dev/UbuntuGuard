#!/usr/bin/env bash
# End-to-end integration test on a real systemd host.
#
# Verifies audit -> backup -> hardening -> verification -> detection ->
# monitoring -> systemd units -> restore against actual ufw, auditd, sshd.
#
# Requirements: root, ubuntuguard installed, jq, ufw, auditd, aide,
# openssh-server. Run from the repository root:
#   sudo OUT_DIR=./integration-out scripts/integration-test.sh
set -uo pipefail

out="${OUT_DIR:-$PWD/integration-out}"
mkdir -p "$out"

pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

check_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1 ($3)"; else bad "$1: expected '$2', got '$3'"; fi
}
check_contains() {
    if grep -qF -- "$2" <<<"$3"; then ok "$1"; else bad "$1: missing '$2'"; fi
}
check_grep() {
    if grep -qiE -- "$2" <<<"$3"; then ok "$1"; else bad "$1: no match for '$2'"; fi
}
has_finding() {
    jq -e --arg id "$2" '.findings[] | select(.id == $id)' "$1" >/dev/null 2>&1
}

echo "== environment =="
# shellcheck disable=SC1091
. /etc/os-release
echo "host      : $(hostname)"
echo "os        : ${PRETTY_NAME:-unknown}"
echo "kernel    : $(uname -r)"
echo "systemd   : $(systemctl --version | head -1)"
echo "ubuntuguard: $(ubuntuguard version)"
echo "output    : $out"

systemctl is-system-running --wait >/dev/null 2>&1 || true

echo
echo "== preconditions =="
ufw --force disable >/dev/null 2>&1 || true
require_auditd="${REQUIRE_AUDITD:-1}"
auditd_state="$(systemctl is-active auditd 2>/dev/null || true)"
if [[ "$auditd_state" == "active" ]]; then
    ok "auditd installed and active"
elif [[ "$require_auditd" == "1" ]]; then
    bad "auditd is not active"
else
    echo "SKIP  auditd is not usable on this kernel ($auditd_state)"
fi
check_eq "ssh service active" "active" "$(systemctl is-active ssh 2>/dev/null || true)"
check_eq "ufw starts inactive" "inactive" "$(ufw status | head -1 | sed 's/^Status: //')"

echo
echo "== doctor =="
ubuntuguard --json doctor >"$out/doctor.json" 2>"$out/doctor.err" || true
if jq -e '.platform' "$out/doctor.json" >/dev/null 2>&1; then
    ok "doctor JSON report"
else
    bad "doctor JSON report"
fi

echo
echo "== audit before hardening =="
ubuntuguard --json audit --fail-on critical >"$out/audit-before.json" || true
before_total=$(jq -r '.summary.total' "$out/audit-before.json")
echo "findings before: $before_total (score $(jq -r '.summary.score' "$out/audit-before.json"))"
if has_finding "$out/audit-before.json" FW-001; then
    ok "FW-001 detected while ufw is inactive"
else
    bad "FW-001 missing while ufw is inactive"
fi
if has_finding "$out/audit-before.json" SSH-002; then
    ok "SSH password authentication finding present"
else
    bad "SSH-002 missing before hardening"
fi

echo
echo "== backup before changes =="
ubuntuguard --json backup create --label integration >"$out/backup-create.json" || true
snapshot=$(jq -r '.snapshot_id // empty' "$out/backup-create.json")
files=$(jq -r '.files // 0' "$out/backup-create.json")
if [[ -n "$snapshot" ]]; then ok "snapshot created: $snapshot ($files files)"; else bad "snapshot creation"; fi

ubuntuguard --json backup verify "$snapshot" >"$out/backup-verify.json" || true
check_eq "snapshot checksum valid" "true" "$(jq -r '.valid' "$out/backup-verify.json" 2>/dev/null)"

ubuntuguard --json backup drill "$snapshot" >"$out/backup-drill.json" || true
drill_files=$(jq -r '.files // 0' "$out/backup-drill.json" 2>/dev/null)
if [[ "$drill_files" -gt 0 && "$drill_files" -le "$files" ]]; then
    ok "snapshot drill restored $drill_files file(s)"
else
    bad "snapshot drill restored $drill_files file(s) of $files recorded"
fi

echo
echo "== harden plan (read-only) =="
ubuntuguard harden plan --only ssh,sysctl,firewall >"$out/harden-plan.txt" 2>&1 || true
plan=$(cat "$out/harden-plan.txt")
check_contains "plan previews ssh drop-in" "PasswordAuthentication no" "$plan"
check_contains "plan previews ufw enable" "ufw --force enable" "$plan"
check_contains "plan previews sysctl drop-in" "net.ipv4.tcp_syncookies" "$plan"
if [[ -f /etc/ssh/sshd_config.d/99-ubuntuguard.conf ]]; then
    bad "plan modified sshd config"
else
    ok "plan did not modify sshd config"
fi

echo
echo "== harden apply =="
ubuntuguard --yes harden apply --apply --only ssh,sysctl,firewall >"$out/harden-apply.txt" 2>&1
rc=$?
check_eq "harden apply exit code" "0" "$rc"
sed -n '1,40p' "$out/harden-apply.txt"

echo
echo "== verification on the live system =="
sshd_eff=$(sshd -T 2>/dev/null || true)
check_grep "sshd PasswordAuthentication no" '^passwordauthentication no' "$sshd_eff"
check_grep "sshd MaxAuthTries 4" '^maxauthtries 4' "$sshd_eff"
check_grep "sshd PermitRootLogin prohibit-password" '^permitrootlogin (prohibit-password|without-password)' "$sshd_eff"
check_eq "sysctl rp_filter applied" "1" "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)"
ufw_status=$(ufw status verbose 2>&1 || true)
check_contains "ufw active" "Status: active" "$ufw_status"
check_contains "ufw default incoming deny" "deny (incoming)" "$ufw_status"

echo
echo "== audit after hardening =="
ubuntuguard --json audit --fail-on critical >"$out/audit-after.json" || true
after_total=$(jq -r '.summary.total' "$out/audit-after.json")
echo "findings after: $after_total (score $(jq -r '.summary.score' "$out/audit-after.json"))"
if has_finding "$out/audit-after.json" FW-001; then
    bad "FW-001 still reported after ufw enabled"
else
    ok "FW-001 cleared after ufw enabled"
fi
if [[ "$after_total" -lt "$before_total" ]]; then
    ok "finding count decreased ($before_total -> $after_total)"
else
    bad "finding count did not decrease ($before_total -> $after_total)"
fi

echo
echo "== detection =="
if [[ "$auditd_state" == "active" ]]; then
    auditctl -w /etc/sudoers -p wa -k ubuntuguard-integration >/dev/null 2>&1 || true
    auditctl -w /etc/ssh -p wa -k ubuntuguard-integration >/dev/null 2>&1 || true
fi
ubuntuguard --json detect --init-baseline >"$out/detect-init.json" 2>"$out/detect-init.err" || true
ubuntuguard --json detect --fail-on critical >"$out/detect.json" 2>"$out/detect.err" || true
if [[ "$auditd_state" == "active" ]]; then
    if has_finding "$out/detect.json" AUD-002; then
        bad "auditd reported inactive although service is running"
    else
        ok "auditd service recognized as active"
    fi
    if has_finding "$out/detect.json" AUD-003; then
        bad "auditd watches not recognized"
    else
        ok "auditd watches for /etc/sudoers and /etc/ssh recognized"
    fi
elif [[ "$require_auditd" == "1" ]]; then
    bad "auditd unavailable, cannot verify audit rules"
else
    echo "SKIP  auditd checks (kernel audit unavailable)"
fi
if has_finding "$out/detect.json" AID-002; then
    ok "AIDE database absence reported (expected on a fresh host)"
else
    echo "INFO  AIDE database present; integrity checks enabled"
fi
if has_finding "$out/detect.json" FILE-001 || has_finding "$out/detect.json" FILE-002; then
    bad "file baseline findings right after initialization"
else
    ok "file baseline clean after --init-baseline"
fi

echo
echo "== monitoring =="
ubuntuguard --json monitor check --no-notify >"$out/monitor.json" 2>"$out/monitor.err" || true
if has_finding "$out/monitor.json" HEALTH-005; then
    bad "ssh reported unhealthy"
else
    ok "ssh service healthy"
fi

echo
echo "== systemd integration =="
ubuntuguard systemd install >"$out/systemd-install.txt" 2>&1 || true
check_eq "audit timer enabled" "enabled" "$(systemctl is-enabled ubuntuguard-audit.timer 2>/dev/null || true)"
check_eq "monitor timer enabled" "enabled" "$(systemctl is-enabled ubuntuguard-monitor.timer 2>/dev/null || true)"
ubuntuguard systemd uninstall >"$out/systemd-uninstall.txt" 2>&1 || true
if [[ -f /etc/systemd/system/ubuntuguard-audit.timer ]]; then
    bad "audit timer unit still present after uninstall"
else
    ok "audit timer unit removed"
fi

echo
echo "== restore from pre-hardening snapshot =="
ubuntuguard --json backup restore "$snapshot" --force >"$out/backup-restore.json" 2>"$out/backup-restore.err" || true
check_eq "restore verified" "true" "$(jq -r '.verified' "$out/backup-restore.json" 2>/dev/null)"
if [[ -f /etc/ssh/sshd_config.d/99-ubuntuguard.conf ]]; then
    bad "ssh drop-in still present after restore"
else
    ok "ssh drop-in removed after restore"
fi
sshd_after=$(sshd -T 2>/dev/null || true)
check_grep "sshd configuration reverted" '^passwordauthentication yes' "$sshd_after"

echo
echo "== combined report =="
ubuntuguard report --format html --out "$out/report.html" >"$out/report.log" 2>&1 || true
size=$(stat -c '%s' "$out/report.html" 2>/dev/null || echo 0)
if [[ "$size" -gt 5000 ]]; then ok "HTML report generated ($size bytes)"; else bad "HTML report missing or too small"; fi

echo
echo "== summary =="
echo "passed: $pass, failed: $fail"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "### UbuntuGuard integration results"
        echo
        echo "| metric | value |"
        echo "| ------ | ----- |"
        echo "| passed checks | $pass |"
        echo "| failed checks | $fail |"
        echo "| audit findings before | $before_total |"
        echo "| audit findings after | $after_total |"
        echo "| snapshot | $snapshot |"
    } >>"$GITHUB_STEP_SUMMARY"
fi

[[ "$fail" -eq 0 ]]
