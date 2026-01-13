from __future__ import annotations

from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Host(BaseModel):
    name: str
    ip: str | None = None


class Source(BaseModel):
    kind: str
    path: str | None = None


Outcome = Literal["success", "failure", "unknown"]


class EventCore(BaseModel):
    type: str
    action: str
    outcome: Outcome
    severity: int = Field(ge=1, le=10)


class User(BaseModel):
    name: str | None = None
    uid: int | None = None


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = None
    domain: str | None = None
    geo: dict[str, Any] | None = None
    asn: dict[str, Any] | None = None


class Process(BaseModel):
    name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    path: str | None = None
    cmdline: str | None = None


class Raw(BaseModel):
    line: str
    parser: str


class NormalizedEvent(BaseModel):
    schema: Literal["minisoc.event.v1"] = "minisoc.event.v1"
    event_id: UUID = Field(default_factory=uuid4)
    ts: str
    host: Host
    source: Source
    event: EventCore
    message: str
    raw: Raw

    user: User | None = None
    src: Endpoint | None = None
    dst: Endpoint | None = None
    process: Process | None = None

    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    enrich: dict[str, Any] = Field(default_factory=dict)
