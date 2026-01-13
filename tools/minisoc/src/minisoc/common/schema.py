from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


class Host(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    ip: str | None = None


class Source(BaseModel):
    model_config = ConfigDict(extra="allow")
    kind: str
    path: str | None = None


class Event(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    action: str
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    severity: int = 3


class Raw(BaseModel):
    model_config = ConfigDict(extra="allow")
    line: str
    parser: str | None = None


class User(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    uid: str | None = None


class NetEndpoint(BaseModel):
    model_config = ConfigDict(extra="allow")
    ip: str | None = None
    port: int | None = None
    geo: dict[str, Any] | None = None  # {lat, lon, country, asn, ...}


class NormalizedEvent(BaseModel):
    """
    NormalizedEvent schema v1 for MiniSOC.

    NOTE:
    - Internal field is schema_id, but JSON uses "schema" (alias) for compatibility.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    schema_id: str = Field(default="minisoc.event.v1", alias="schema")
    ts: str  # RFC3339 string
    event_id: UUID = Field(default_factory=uuid4)

    host: Host
    source: Source
    event: Event

    message: str
    raw: Raw

    user: User | None = None
    src: NetEndpoint | None = None

    tags: list[str] = Field(default_factory=list)

    @classmethod
    def from_parts(
        cls,
        *,
        ts: str,
        host_name: str,
        host_ip: str | None,
        source_kind: str,
        source_path: str,
        event_type: str,
        event_action: str,
        outcome: str,
        severity: int,
        message: str,
        raw_line: str,
        parser: str,
        user: str | None = None,
        src_ip: str | None = None,
        src_port: int | None = None,
        tags: list[str] | None = None,
    ) -> "NormalizedEvent":
        return cls(
            schema_id="minisoc.event.v1",
            ts=ts,
            host=Host(name=host_name, ip=host_ip),
            source=Source(kind=source_kind, path=source_path),
            event=Event(type=event_type, action=event_action, outcome=outcome, severity=severity),
            message=message,
            raw=Raw(line=raw_line, parser=parser),
            user=User(name=user) if user else None,
            src=NetEndpoint(ip=src_ip, port=src_port) if (src_ip or src_port) else None,
            tags=tags or [],
        )
