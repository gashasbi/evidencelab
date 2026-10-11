# Evidence Standard 1.0

## Purpose

The Evidence Standard defines the minimum semantic discipline expected of a reusable Evidence Pattern in EvidenceLab. The artifact contract provides structure; the standard describes the proof discipline needed for meaningful results.

A schema-valid file can still encode a poor hypothesis. Structural validation is necessary but not sufficient for semantic review, research-grade audit, or external validation.

## Required separation

An Evidence Pattern must preserve the distinction between:

1. external truth declarations and dataset labels;
2. raw analyzer observations;
3. derived facts and their input lineage;
4. proof obligations stated by the researcher;
5. a coherent witness satisfying those obligations;
6. counter-evidence that may refute or qualify the witness;
7. final evaluation outcomes.

## Proof discipline

For every required claim, the author should document the object or relation being established, the source of each relevant fact, the binding under which the claim is evaluated, the behavior when information is missing, and the known limitations of the analyzer substrate.

At minimum, reviewers should assess:

- object identity and binding coherence;
- data-flow, control-flow, or other relation requirements as appropriate;
- size, range, and type assumptions for quantitative claims;
- counter-evidence and safe variants;
- uncertainty when analysis is incomplete;
- bounded search and candidate truncation;
- provenance for derived facts;
- tests designed to falsify the definition.

## Analyzer independence

A reusable definition should use the canonical graph and semantic relations where possible. When raw Joern or another analyzer's syntax is used directly, document the dependency and do not claim analyzer independence without evidence.

## Promotion to research-grade use

Before making a research claim, pair pattern review with benchmark quality checks, independent test cases, repository/project-aware or chronological partitions as appropriate, leakage and lineage audits, witness replay, provenance checks, and external validation. The bundled examples are reference fixtures, not a substitute for this evidence.
