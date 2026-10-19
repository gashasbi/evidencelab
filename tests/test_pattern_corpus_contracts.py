import hashlib, json, subprocess, sys
import pytest
from evidencelab.spec import Pattern

def test_core_patterns_load(repo_root):
    for path in (repo_root/"examples/cwe-121/evidence-pattern.json",
        repo_root/"examples/cwe-121/families/unbounded-copy/pattern.json",
        repo_root/"examples/cwe-121/families/fixed-write/pattern.json"):
        assert path.is_file(), path
        p=Pattern.load(path)
        assert p.pattern_id
        assert p.unknown_policy in {"unknown","partial","non_match"}

def test_unbounded_copy_pattern_declares_tri_state_unknown_policy(repo_root):
    raw=json.loads((repo_root/"examples/cwe-121/families/unbounded-copy/pattern.json").read_text(encoding="utf-8"))
    assert raw.get("evidence_contract",{}).get("unknown_policy")=="unknown"
    assert raw.get("evidence_contract",{}).get("tri_state") is True

def test_benchmark_manifest_has_cases_and_expected_labels(repo_root):
    raw=json.loads((repo_root/"examples/cwe-121/benchmark.json").read_text(encoding="utf-8"))
    assert raw.get("cases"), "benchmark manifest unexpectedly has no cases"
    for case in raw["cases"]:
        assert case.get("id")
        assert case.get("expected") in {"MATCH","NO_MATCH","UNKNOWN","PARTIAL"}

def test_optional_c_security_corpus_validator(repo_root):
    validator=repo_root/"examples/c-security-corpus/tools/validate_corpus.py"
    if not validator.is_file(): pytest.skip("optional c-security-corpus is not present")
    p=subprocess.run([sys.executable,str(validator)],cwd=repo_root,text=True,capture_output=True,timeout=60)
    assert p.returncode==0,p.stdout+"\\n"+p.stderr

def test_optional_corpus_sha256sums(repo_root):
    sums=repo_root/"examples/c-security-corpus/metadata/SHA256SUMS"
    if not sums.is_file(): pytest.skip("optional corpus SHA256SUMS is not present")
    failures=[]
    for line in sums.read_text(encoding="utf-8").splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        digest,rel=line.split(maxsplit=1); rel=rel.lstrip("* ")
        target = sums.parent.parent / rel
        if not target.is_file(): failures.append(f"missing: {target}")
        elif hashlib.sha256(target.read_bytes()).hexdigest()!=digest: failures.append(f"digest mismatch: {target}")
    assert not failures, failures
