# Residual risk

Known gaps of the deterministic layers (rules plus the heuristic semantic
pass, no LLM judge), measured by `python3 scripts/bench_policy.py` on the
in-repo corpus. Generated with `--update-baseline`; edit the reasons in
`tests/fixtures/corpus/sources.yaml` (`residual:`), not here.

Attack cases: 118, detected (warn or block): 118 (100.0%). Benign cases: 439, blocked: 2 (0.5%), warned: 10.

Case ids name the test or template that holds the case.

Scope of these numbers:

- The attack half is harvested from the repo's own regression tests and
  starter pack, which were written to pass. A full detection rate here
  means no regression on known cases. It does not estimate how much of
  an unseen technique the rules catch.
- Only literal test values are harvested; computed ones (f-strings,
  encoded at test time) are skipped (14 this run).
- The LLM judge, the supply-chain install check (registry and OSV lookups),
  and org, user or project policy layers are out of scope. Judge figures
  quoted elsewhere in the docs were measured outside the repo.

## Not detected (0)

None.

## Detected at a lower verdict than expected (0)

None.

## Benign cases blocked (2)

| Case | Category | Reason |
| --- | --- | --- |
| `benign/file_read/dc398bda` | benign_file_read | The secret-access path pattern matches every `.env.*` name, so a values-free `.env.example` template is blocked on Read; the shell-read rule already exempts it. |
| `benign/file_write/552e4e37` | benign_file_write | Same `.env.*` path pattern as above, applied to a write of an example template. |

