from __future__ import annotations
import json, urllib.request, zipfile, xml.etree.ElementTree as ET
from pathlib import Path

OFFICIAL_XML_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def sync_catalog(destination: str | Path, url: str = OFFICIAL_XML_ZIP) -> dict:
    d = Path(destination)
    d.parent.mkdir(parents=True, exist_ok=True)
    raw = urllib.request.urlopen(url, timeout=60).read()
    entries = {}
    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as z:
        name = next((x for x in z.namelist() if x.lower().endswith(".xml")), None)
        if not name:
            raise RuntimeError("CWE archive has no XML")
        root = ET.fromstring(z.read(name))
    for el in root.iter():
        if el.tag.endswith("Weakness"):
            wid = el.attrib.get("ID")
            nm = el.attrib.get("Name")
            if wid and nm and wid.upper().startswith("CWE-"):
                descriptions = []
                for x in el.iter():
                    if x.tag.endswith("Description") and x.text:
                        descriptions.append(x.text)
                entries[wid.upper()] = {
                    "id": wid.upper(),
                    "name": nm,
                    "description": " ".join(" ".join(descriptions).split()),
                }
    payload = {
        "source": "MITRE CWE",
        "source_url": url,
        "entry_count": len(entries),
        "entries": entries,
    }
    d.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(d), "count": len(entries)}


def load_catalog(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def get(catalog: dict, cwe_id: str):
    return catalog.get("entries", {}).get(cwe_id.upper())
