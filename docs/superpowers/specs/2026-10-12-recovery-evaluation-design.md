# Recovery evaluation design

用户已批准上一轮提出的顺序：DDS 超时排查、受控缺陷检出、多种子对照、机制消融。继续当前 feature 分支和未提交工作，不提交、推送或部署。

## Architecture

Extend existing offline scenario/campaign tools, not ROS control interfaces. Add startup diagnostics (expected/actual ROS domain, process ready/first message timestamps, whitelisted child environment, discovery counts) to the existing launch test. Reproduce startup with simultaneous pytest and serial runs; only change startup behavior when evidence identifies a cause. If transient cannot be reproduced, explicitly keep root cause unconfirmed rather than claim a fix.

Add predefined AST mutations of repository-owned protocol/coordinator code in experiment-only modules. Fail closed if a mutation no longer matches its expected AST site. Compile into separate namespaces; never edit or monkeypatch production modules or expose variants to ROS nodes. Variants: expired permits accepted; context binding disabled (observe/consume/continuation checks); replayed permits accepted; independent observation omitted. Record exact disabled checks and source hashes. Trace/oracle inputs retain original physical/software observation and exact bindings.

Extend scenario with a replay-permit attempt that calls the real protocol authorization entry point, and parameterize only the offline executor. Qualification runs deterministic challenge scenarios for each defect, paired with full-mechanism controls; save actions/raw frames/violation codes and verify exact replay. Attempt Hypothesis find reduction; distinguish not-rediscovered from minimized and do not claim globally smallest inputs.

Batch evaluation uses seeds 0..9, 1000 actual generated tests per guided/unguided group, with fixed scenarios as an explicitly labeled cyclic reference. Generated groups receive no fixed seed scenarios. Same strategy, configuration, candidate order limit, defect screening rules, and budget. Conservative screening may skip a mutant only when its affected path is absent; report screening and execution counts. Report coverage, wall-clock cost, unique seeded defect families, first generated test index/time, and raw violation codes. Injected defects are test sensitivity/ablation evidence, not vulnerabilities discovered in the production system.

Each generated sequence executes the unmodified core. Mutant evaluations exercise the actual changed core when the sequence reaches a relevant path. Metrics deduplicate by predefined defect family; report codes separately, not as independent vulnerabilities. Aggregate per seed with median/range and paired differences; no unsupported significance claim. Save per-run reports and interesting corpora; first-defect inputs are replayable with variant identity.

Ablation evaluates all variants on the same curated challenges and recovery repair sequences. Report invalid-evidence mission authorization, unsafe permit consumption, observed repair delay and eligible-stall count. Full controls must remain clean, recover after repair and detect seeded defects. No physical braking certification, arbitrary DDS fuzzing, BTreeFuzz algorithm reproduction, Nav2 or general IDS clearance implementation in this iteration.

## Acceptance

- Startup diagnostics contain no signing secrets; domain/process readiness evidence survives timeout.
- Each of four defect families is detected on its paired challenge; full controls have no violations.
- First defects and reduced counterexamples replay deterministically; mutation configuration never affects default scenarios or ROS imports.
- Complete ten-seed/1000-example guided/unguided runs, preserve reports, compare with labeled fixed reference.
- Existing/new tests, Humble build and real three-process acceptance pass; review important findings resolved.
- Document results honestly, including any negative feedback result and unconfirmed startup cause.
