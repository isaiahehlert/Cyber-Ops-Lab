from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from minisoc.common.schema import NormalizedEvent


class Storage(ABC):
    @abstractmethod
    def init(self) -> None: ...

    @abstractmethod
    def insert_events(self, events: Iterable[NormalizedEvent]) -> int: ...

    @abstractmethod
    def recent_events(self, limit: int = 50) -> list[dict]: ...
