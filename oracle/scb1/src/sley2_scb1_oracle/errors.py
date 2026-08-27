"""Stable SCB1 oracle failures."""


class ScbError(ValueError):
    """A strict SCB1 rejection with its stable public code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
