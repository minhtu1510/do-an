"""Historian service — reads real samples written by main.py's on_tag_update hook.

No synthetic data: configured() reflects whether the historian DB is wired up
(always True now), and both queries return exactly what insert_sample stored.
"""

from ..database import query_process_history, query_tag_history


class HistoryUnavailable(RuntimeError):
    pass


class HistoryService:
    def configured(self) -> bool:
        return True

    def tag_history(self, key: str, start: str | None, end: str | None) -> list[dict]:
        return query_tag_history(key, start, end)

    def process_history(self, tag_keys: list[str], start: str | None, end: str | None) -> dict[str, list[dict]]:
        return query_process_history(tag_keys, start, end)


history_service = HistoryService()
