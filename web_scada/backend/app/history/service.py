"""Historian service placeholder.

The trends page should not present fake historical data before PostgreSQL is
configured, so this service currently reports that history is unavailable.
"""


class HistoryUnavailable(RuntimeError):
    pass


class HistoryService:
    def configured(self) -> bool:
        return False


history_service = HistoryService()
