from __future__ import annotations
import sys
from .capabilities import detect


def run():
    caps = detect()
    return {
        "python": {"version": sys.version, "executable": sys.executable},
        "joern": {
            "version": caps.get("joern_version"),
            **caps.get("commands", {}),
        },
        "notes": [
            "Use a project-local virtual environment on PEP-668 systems.",
            "Joern command availability does not by itself prove semantic-analysis completeness.",
            "EvidenceLab records analysis incompleteness as UNKNOWN rather than silently upgrading it to proof.",
        ],
    }
