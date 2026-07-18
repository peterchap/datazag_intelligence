#!/usr/bin/env bash
# estates/run_all.sh — collect + render the three validation estates.
#
# Each estate is a real-world shape we want the cross-estate analytics tested
# against before committing to the diligence-cut spec:
#
#   vc_portfolio  N independent companies, no shared infrastructure — does
#                 concentration mean anything across an unrelated book?
#   large_org     one parent, many brands/ccTLDs/acquisitions — the design case.
#   nursery_group an acquisitive rollup — the M&A diligence shape, where the
#                 neglected acquired-brand tail is the finding.
#
# Usage:  bash estates/run_all.sh [estate ...]     (default: all three)
# Needs a real INTELLIGENCE_API_KEY in .env, or pass --local on the master host.

set -uo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-./venv/Scripts/python.exe}
[ -x "$PY" ] || PY=python
COLLECT_ARGS=${COLLECT_ARGS:-}

ESTATES=("$@")
[ ${#ESTATES[@]} -eq 0 ] && ESTATES=(vc_portfolio large_org nursery_group)

for name in "${ESTATES[@]}"; do
  dir="estates/$name"
  if [ ! -f "$dir/domains.csv" ]; then
    echo "!! $name: no $dir/domains.csv — skipping"
    continue
  fi

  echo ""
  echo "=============================================================="
  echo "  $name"
  echo "=============================================================="

  # shellcheck disable=SC2086
  "$PY" estate_collect.py --domains "$dir/domains.csv" --out "$dir" \
      --group "$name" --resume $COLLECT_ARGS || { echo "!! $name: collect failed"; continue; }

  # crossestate MVP — both human cuts. PDF skipped: Playwright is absent locally.
  "$PY" estate_run.py --manifest "$dir/manifest.json" \
      --cut all --format json,html,markdown --skip-pdf || echo "!! $name: estate_run failed"

  # estatereport v2.2 — the 6-page + Appendix A paid-tier report.
  "$PY" estate_report_run.py --manifest "$dir/manifest.json" \
      --format json,html,markdown --skip-pdf || echo "!! $name: estate_report_run failed"
done

echo ""
echo "Done. Reports in output/estate/<group>/"
