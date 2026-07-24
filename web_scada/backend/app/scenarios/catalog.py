"""Loads tests/day8/scenarios.yaml so incoming scenario results can be
enriched with their MITRE ATT&CK for ICS technique mapping without the
runner (attacker/controller host) having to send it over the wire.

mitre_technique values in that file were verified live against
attack.mitre.org/matrices/ics/, not guessed.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
CATALOG_PATH = REPO_ROOT / "tests" / "day8" / "scenarios.yaml"


class ScenarioCatalog:
    def __init__(self, path: Path = CATALOG_PATH):
        self.path = path
        self._by_id: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        self._by_id.clear()
        if not self.path.is_file():
            return
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        for group in (data.get("groups") or {}).values():
            for scenario in group.get("scenarios", []):
                scenario_id = scenario.get("id")
                if not scenario_id:
                    continue
                self._by_id[scenario_id] = {
                    "mitre_technique": scenario.get("mitre_technique"),
                    "mitre_technique_name": scenario.get("mitre_technique_name"),
                }

    def lookup(self, scenario_id: str) -> dict:
        return self._by_id.get(scenario_id, {"mitre_technique": None, "mitre_technique_name": None})


scenario_catalog = ScenarioCatalog()
