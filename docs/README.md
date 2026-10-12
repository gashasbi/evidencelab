# Documentation index

Use the page that matches the task. The basic path is **Installation → Quickstart**; specialist pages are reference material, not required reading for every user.

## Get running

| Page | Use it when… |
|---|---|
| [Installation](installation.md) | Creating a virtual environment, installing runtime/development extras, or verifying a package install. |
| [Quickstart](quickstart.md) | Running the bundled ELS against the reference vulnerable and safe graphs. |
| [Troubleshooting](troubleshooting.md) | A command, import, test, or Joern capture fails. |
| [CLI reference](cli-reference.md) | Looking up command purpose and common arguments. The installed command's `--help` is authoritative. |

## Understand and author Evidence

| Page | Use it when… |
|---|---|
| [Architecture](architecture.md) | Understanding data flow between ELS, graph inputs, the matcher, and research artifacts. |
| [Evidence model](evidence-model.md) | Interpreting proof states, outcomes, witnesses, counter-evidence, and uncertainty. |
| [ELS reference](evidence-dsl.md) | Writing or reviewing ELS syntax, selectors, claims, witnesses, and execution policies. |

## Bring data and analyzers

| Page | Use it when… |
|---|---|
| [Dataset integration](dataset-integration.md) | Importing SARD/Juliet or mapping your own records and source files. |
| [Joern integration](joern-integration.md) | Installing Joern, capturing source, inspecting artifacts, or testing live integration. |
| [Security model](security-model.md) | Handling untrusted code, external archives, credentials, or hidden benchmarks. |

## Plan, evaluate, and preserve research

| Page | Use it when… |
|---|---|
| [Research methodology](research-methodology.md) | Taking a hypothesis through observations, Evidence, data selection, evaluation, and external validation. |
| [Benchmark design](benchmark-design.md) | Designing positive, negative, unknown, mutation, leakage, and metric checks. |
| [Research task and submission](research-task-and-submission.md) | Defining a task contract or packaging a reviewable research submission. |
| [Reproducibility](reproducibility.md) | Recording artifact identities, indexing files, replaying witnesses, or bundling results. |
| [References](references.md) | Finding upstream standards and tools and understanding what EvidenceLab does—and does not—claim about them. |

Commands and examples assume execution from the repository root and an active virtual environment, unless stated otherwise. Files written under `/tmp` are disposable examples. A `PASS` only means that the checks performed by that command passed; it is not proof of external validity.
