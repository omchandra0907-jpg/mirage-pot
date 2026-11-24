"""JSONL Session Recorder and Inter-Keystroke Timing Engine."""

import json
import os
import time
from dataclasses import asdict, dataclass
from typing import TextIO


@dataclass
class SessionEvent:
    timestamp_ms: int
    session_id: str
    src_ip: str
    username: str
    event_type: str  # "auth_attempt", "auth_success", "command", "disconnect"
    command: str = ""
    mitre_id: str | None = None
    mitre_name: str | None = None
    output: str = ""
    delay_ms: int = 0


class SessionRecorder:
    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        self._file: TextIO | None = None
        self._last_event_time: float = time.time()

    def open(self):
        if not self._file:
            self._file = open(self.log_path, "a", encoding="utf-8")

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def record_event(
        self,
        session_id: str,
        src_ip: str,
        username: str,
        event_type: str,
        command: str = "",
        mitre_id: str | None = None,
        mitre_name: str | None = None,
        output: str = "",
    ) -> SessionEvent:
        now = time.time()
        delay_ms = int((now - self._last_event_time) * 1000)
        self._last_event_time = now

        event = SessionEvent(
            timestamp_ms=int(now * 1000),
            session_id=session_id,
            src_ip=src_ip,
            username=username,
            event_type=event_type,
            command=command,
            mitre_id=mitre_id,
            mitre_name=mitre_name,
            output=output,
            delay_ms=delay_ms,
        )

        if not self._file:
            self.open()

        assert self._file is not None
        self._file.write(json.dumps(asdict(event)) + "\n")
        self._file.flush()
        return event
