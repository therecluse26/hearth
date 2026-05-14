"""Hearth API error type."""

from typing import Optional, Any


class HearthError(Exception):
    """Raised when the Hearth API returns an error response."""

    def __init__(self, status_code: int, message: str, details: Optional[dict] = None):
        self.status_code = status_code
        self.message = message
        self.details = details
        super().__init__(f"HTTP {status_code}: {message}")
