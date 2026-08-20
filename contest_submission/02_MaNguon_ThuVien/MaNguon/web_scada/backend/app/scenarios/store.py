"""In-memory store for day8 attack scenario runs, pushed by tests/day8/run_day8.py.

Same lightweight pattern as events.service.EventService — no fake data is
ever synthesized here, only what the runner actually reports.
"""

from collections import deque

from .models import ScenarioResult

TERMINAL_IMPACT_STATUSES = {"EXECUTED", "EXECUTED_GATED", "FAILED"}


class ScenarioStore:
    def __init__(self, max_results: int = 500):
        self._results: deque[ScenarioResult] = deque(maxlen=max_results)

    def add(self, result: ScenarioResult) -> ScenarioResult:
        self._results.appendleft(result)
        return result

    def list(self, limit: int = 50) -> list[dict]:
        safe_limit = max(1, min(limit, 500))
        return [r.to_dict() for r in list(self._results)[:safe_limit]]

    def latest(self) -> ScenarioResult | None:
        return self._results[0] if self._results else None

    def executed_count(self) -> int:
        return sum(1 for r in self._results if r.status in TERMINAL_IMPACT_STATUSES)

    def security_mode_comparator(self, group: str = "opcua") -> dict:
        """Latest real result per (scenario_id, security_mode) for one group.

        Only results that carried a security_mode (set by the operator via
        OPCUA_SECURITY_MODE when running tests/day8/run_day8.py) are used.
        A cell is missing (None) until that scenario has actually been run
        under that mode -- nothing here is inferred or filled in.
        """
        modes_seen: list[str] = []
        latest: dict[tuple[str, str], ScenarioResult] = {}

        # self._results is newest-first (appendleft), so the first match per
        # key is already the latest one.
        for r in self._results:
            if r.group != group or not r.security_mode:
                continue
            if r.security_mode not in modes_seen:
                modes_seen.append(r.security_mode)
            key = (r.scenario_id, r.security_mode)
            if key not in latest:
                latest[key] = r

        scenario_ids = sorted({sid for sid, _mode in latest.keys()})
        rows = []
        for sid in scenario_ids:
            row: dict = {"scenario_id": sid}
            for mode in modes_seen:
                result = latest.get((sid, mode))
                row[mode] = result.to_dict() if result else None
            rows.append(row)

        return {"group": group, "security_modes": modes_seen, "rows": rows}

    def summary(self) -> dict:
        latest = self.latest()
        return {
            "total_runs": len(self._results),
            "executed_count": self.executed_count(),
            "latest_scenario_id": latest.scenario_id if latest else None,
            "latest_group": latest.group if latest else None,
            "latest_status": latest.status if latest else None,
            "latest_received_at": latest.received_at if latest else None,
        }


scenario_store = ScenarioStore()
