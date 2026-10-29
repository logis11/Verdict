#!/usr/bin/env bash
# EVAL-KNOWNCVE-1028: srvnet-9444 known-CVE evaluation run
# Verdict static-only, cumulative mode (FRESH=0), eval candidates pre-seeded
set -euo pipefail

export MODEL=claude-opus-5
export FRESH=0                      # 기존 원장 누적
export CASE_TIMEOUT=3600            # 1시간
export MAX_TURNS=120
export MAX_TOOL_CALLS=250
export RUN_TAG=eval-srvnet-1028-r2

# 게이트 전부 켬
export GATE_DISASM=1
export GATE_CONTROL=1
export GATE_ANCHOR=1
export GATE_REJECT=1
export GATE_STOP=1

# 실측 전부 끔 (static-only)
export ALLOW_PROBE=0
export ALLOW_VM_PROBE=0
export ALLOW_KDNET=0
export ALLOW_QEMU_LAB=0

# SETTING_SOURCES=user → ~/.claude/CLAUDE.md 로드 (방법론만, 표적 자료 없음)
export SETTING_SOURCES=user

# GOAL (400자 이내)
export OPERATOR_GOAL="surface 7건(SrvLibAuditShareModification 0x1400287e0, SrvLibAuditShareAddOrDelete 0x140011020, SrvLibApplySrvDeviceAcl 0x140050490, SrvLibApplyDeviceAcl 0x1400587d0, fn_140012d60, fn_140003fd0, fn_140011b50)을 각각 디스어셈블하고 메모리안전 결함을 찾아 verdict하라. clean이면 clean verdict. 7건 전부 판정하라."
export OPERATOR_GOAL_KIND=judge
export OPERATOR_GOAL_BY=operator

cd /home/kinn/projects/Verdict

echo "=== EVAL-KNOWNCVE-1028 ==="
echo "target: work/bin/srvnet-9444.sys"
echo "ledger: state/srvnet-9444.sys.json (FRESH=0, cumulative)"
echo "model:  $MODEL"
echo "timeout: $CASE_TIMEOUT"
echo "tag:    $RUN_TAG"
echo ""

python3 -m verdict.agent_sdk work/bin/srvnet-9444.sys 2>&1 | tee work/logs/eval-srvnet-1028.log
