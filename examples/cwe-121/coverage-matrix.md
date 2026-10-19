# CWE-121 coverage and acceptance matrix

## What this package claims

This package currently contains two executable Evidence families, not a universal CWE-121 detector:

1. `fixed-write`: a proven fixed byte extent exceeds the proven byte capacity of one automatic local array, with a coherent source/write/destination/object binding.
2. `unbounded-copy`: an unbounded string-copy-like operation writes to one automatic local array, with a coherent binding. It does not claim a numeric overwrite length.

The existing graph benchmark contains 47 fixed-write cases and 40 unbounded-copy cases (87 total). These are reference/development fixtures, not 87 independent real-world programs and not publication-scale evidence.

## Source-level smoke corpus

`source-cases.json` maps each checked-in C/C++ source case to the family hypotheses it is intended to challenge. `scripts/joern_e2e.sh` captures and merges each source; it then calls `scripts/cwe121_source_evaluate.py` to evaluate the merged graph against both patterns.

The source expectations are falsifiable hypotheses. Review `cwe121-evaluation-report.json`, especially `MISMATCHES_FOUND` and `INCONCLUSIVE`. A `NO_MATCH` on an incomplete graph is not a successful negative. The `--strict` option (or `EVIDENCELAB_E2E_STRICT=1`) fails on mismatches and inconclusive/out-of-scope results.

Run:

```bash
python -m pytest -q tests/test_cwe121_source_corpus.py
./scripts/joern_e2e.sh /tmp/evidencelab-cwe121-e2e
python scripts/cwe121_source_evaluate.py /tmp/evidencelab-cwe121-e2e --strict
```

The Joern command requires `joern-parse`, `joern-export`, and `joern-slice` in `PATH`. The package does not install Joern.

## Coverage dimensions exercised

| Dimension | Current evidence |
|---|---|
| Positive fixed-extent writes | Canonical graph benchmark; C/C++ source hypotheses |
| Safe fixed extent | Canonical graph benchmark; `N01_safe_memcpy.c`, `N04_safe_strncpy.c` |
| Unbounded string copy | Canonical graph benchmark; `strcpy`, `strcat`, wide-string source hypotheses |
| Static-storage discriminator | Canonical graph benchmark; `N02_static.c` |
| Heap discriminator | Canonical graph benchmark; `N03_heap_memcpy.c` |
| Symbolic extent | Canonical graph benchmark; `U01_symbolic_extent.c` |
| Constant arithmetic extent | Canonical graph benchmark; `P07_fixed_expression_extent.c` |
| Interprocedural same-file wrapper | Canonical graph benchmark; `P04_wrapper.c` |
| Wide-character unit uncertainty | `U02_wide_memmove.c`; must not be silently interpreted as bytes |
| C++ translation unit | `P10_cpp_fixed_memcpy.cpp` |
| Incomplete graph / outcome integrity | Canonical graph benchmark and matcher regression tests |

## Explicit exclusions and limitations

The following are not established as supported by these two families and must not be counted as covered merely because a source file is present:

- indexed writes and loop-bound/off-by-one reasoning (`P05_loop.c`);
- arbitrary pointer arithmetic;
- formatted output (`sprintf`) and input APIs such as `scanf`;
- multi-file source-to-sink behavior from real Joern captures;
- general alias analysis, path-sensitive range analysis, and arbitrary user-defined wrappers;
- external real-world precision/recall or publication-grade generalization.

These need separate, falsifiable Evidence definitions and suitable source/graph evidence before they can be claimed. Adding them to the core matcher by guessing would violate EvidenceLab's evidence-first design.

## Acceptance criteria

A review candidate is ready for a local reference run when:

- source manifest entries are unique and point to existing files;
- all source examples pass available C/C++ syntax checks;
- the existing isolated test suite and `research-check --root examples/cwe-121 --profile profiles/research-grade-c-cpp-joern.json --enforce-gates` pass;
- the live Joern report contains no unexplained mismatches;
- incomplete/degraded cases remain inconclusive rather than being counted as safe negatives;
- documentation continues to distinguish reference fixtures from independent real-world validation.
