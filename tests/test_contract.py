def test_portable_inventory_resolves_root_relative_to_manifest(tmp_path):
    from evidencelab.contract import write_research_inventory, verify_research_inventory

    root = tmp_path / "package"
    (root / "provenance").mkdir(parents=True)
    (root / "README.md").write_text("hello\n", encoding="utf-8")
    manifest = root / "provenance" / "research-inventory.json"
    payload = write_research_inventory(root, manifest)
    moved = tmp_path / "moved" / "package"
    import shutil

    shutil.copytree(root, moved)
    result = verify_research_inventory(moved / "provenance" / "research-inventory.json")
    assert result["status"] == "PASS", result
