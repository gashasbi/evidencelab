# CWE-120 Research Basis

## 1. Authoritative definition
MITRE CWE-120 (version 4.20) defines the weakness as copying an input buffer to an output buffer without verifying that the input size is less than the output size. Its demonstrative examples include `scanf("%s", last_name)`, `strcpy`, and `gets`; MITRE also notes that the weakness can arise from data arriving from a host/network source. The entry is a Base-level weakness, not a rule tied to stack storage.

## 2. Evidence interpretation
We therefore separate three claims that are often incorrectly conflated:

1. **Concrete overflow proof**: the write extent (or a proven lower bound on every possible extent) exceeds proven byte capacity.
2. **Root-cause proof**: an unbounded copy/input operation targets a finite-capacity destination without a proven size bound. This is evidence of the CWE-120 class, but does not establish exact overflow magnitude.
3. **Exploitability/source control**: attacker influence, reachable execution, corruption distance, or control-flow impact. These are separate dimensions and are not implied by a root-cause MATCH.

## 3. Evidence dimensions
The research packages test operation semantics, argument roles, destination/target identity, byte capacity, fixed extent, symbolic range, unboundedness, data flow, storage region, guards, source controllability, incomplete analysis, interprocedural labels, pointer/alias-style variants, and adversarial mutations.

## 4. Why multiple Evidence Families
CWE-120 is broad. NIST's Juliet C/C++ suites explicitly vary control and data flow, including same-function, interprocedural, cross-file, pointer/reference, globals, arrays, structs, function pointers, and other propagation forms. Juliet C/C++ 1.3 contains 64,099 tests organized across 118 CWEs; Juliet 1.2 is deprecated but remains a historical reference.

## 5. Tool semantics
Joern exposes code property graphs and data-flow queries/slices. Joern's QueryDB guidance says queries should have unit tests that serve as specifications. The framework uses semantic aliases such as `DATA_FLOW` -> `REACHING_DEF` rather than binding researcher patterns to one raw exporter spelling.

## 6. Range proof
A range claim is proven only when the complete possible interval relation is safe to assert. For `extent > capacity`, PROVEN requires `lower(extent) > upper(capacity)`. Overlap is UNKNOWN. This mirrors the conservative use of lower/upper bounds in established C/C++ range-analysis tooling.

## 7. Capacity proof
Capacity is treated as a byte quantity only when byte width is known. For `char[N]`, byte capacity is deterministic because a char occupies one byte. For non-char arrays, element count alone is not silently treated as byte capacity. Allocator capacity is proven only when the allocation-size expression itself is deterministically resolved.

## 8. Counter-evidence
A candidate witness can be refuted by a proven safe bound or a proven dominating safety guard. The guard must be linked to the same sink witness; a guard somewhere else in the graph is not accepted.

## 9. Unknown discipline
Missing value/range/object identity, incomplete analysis, candidate truncation, or unproven guards remain UNKNOWN. UNKNOWN never becomes a positive match.

## Sources
- MITRE CWE-120: https://cwe.mitre.org/data/definitions/120.html
- NIST Juliet C/C++ 1.3: https://samate.nist.gov/SARD/test-suites/112Software
- Joern CPG slicing: https://docs.joern.io/cpg-slicing/
- Joern data-flow steps: https://docs.joern.io/cpgql/data-flow-steps/
- Joern QueryDB: https://github.com/joernio/joern/blob/master/querydb/README.md
- CodeQL C/C++ data flow: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/
- CodeQL range analysis: https://codeql.github.com/docs/codeql-language-guides/using-range-analsis-in-cpp/
- SEI CERT STR07-C: https://wiki.sei.cmu.edu/confluence/display/c/STR07-C.%2BUse%2Bthe%2Bbounds-checking%2Binterfaces%2Bfor%2Bstring%2Bmanipulation
- SEI CERT MEM35-C: https://wiki.sei.cmu.edu/confluence/display/c/MEM35-C.+Allocate+sufficient+memory+for+an+object
- OASIS SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
