"""AsyncSSH Honeypot Server with Banner Spoofing and Stateful SSH Shell."""

import asyncio
import os
import uuid
import asyncssh
from typing import Dict, Optional, Callable

from .detector import classify_command
from .recorder import SessionRecorder, SessionEvent
from .vfs import VirtualShell

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, recorder: SessionRecorder, event_callback: Optional[Callable[[SessionEvent], None]] = None):
        self.recorder = recorder
        self.event_callback = event_callback
        self.session_id = str(uuid.uuid4())[:8]
        self.src_ip = "127.0.0.1"
        self.username = "root"

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        peer = conn.get_extra_info("peername")
        if peer:
            self.src_ip = peer[0]

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.username = username
        self.recorder.record_event(
            session_id=self.session_id,
            src_ip=self.src_ip,
            username=username,
            event_type="auth_attempt",
            command=f"AUTH password='{password}'",
        )
        # Accept common credentials (e.g. root/root, admin/admin, ubuntu/ubuntu, or any)
        ev = self.recorder.record_event(
            session_id=self.session_id,
            src_ip=self.src_ip,
            username=username,
            event_type="auth_success",
            command=f"LOGIN SUCCESS ({username})",
        )
        if self.event_callback:
            self.event_callback(ev)
        return True

class HoneypotShellSession(asyncssh.SSHServerSession):
    def __init__(self, server: HoneypotSSHServer):
        self.server = server
        self.shell = VirtualShell(server.session_id, server.username)
        self.chan: Optional[asyncssh.SSHServerChannel] = None
        self.input_buf = ""

    def connection_made(self, chan: asyncssh.SSHServerChannel):
        self.chan = chan

    def shell_requested(self) -> bool:
        return True

    def session_started(self):
        assert self.chan is not None
        welcome = (
            f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f" * Support:        https://ubuntu.com/pro\r\n\r\n"
            f"System information as of Tue Nov 24 12:00:00 UTC 2026\r\n\r\n"
            f"  System load:  0.08               Processes:             104\r\n"
            f"  Usage of /:   14.2% of 48.29GB   Users logged in:       1\r\n"
            f"  Memory usage: 22%                IPv4 address for eth0: 10.0.4.15\r\n\r\n"
            f"Last login: Tue Nov 24 11:42:10 2026 from 192.168.1.100\r\n"
        )
        self.chan.write(welcome)
        self._prompt()

    def _prompt(self):
        if not self.chan:
            return
        prompt_char = "#" if self.shell.username == "root" else "$"
        p = f"{self.shell.username}@prod-srv-edge-01:{self.shell.cwd}{prompt_char} "
        self.chan.write(p)

    def data_received(self, data: str, datatype: asyncssh.DataType):
        if not self.chan:
            return
        for char in data:
            if char in ("\r", "\n"):
                self.chan.write("\r\n")
                line = self.input_buf.strip()
                self.input_buf = ""
                if line:
                    if line == "exit":
                        self.chan.write("logout\r\n")
                        self.chan.close()
                        return

                    tech = classify_command(line)
                    out = self.shell.execute(line)
                    if out:
                        self.chan.write(out.replace("\n", "\r\n") + "\r\n")

                    ev = self.server.recorder.record_event(
                        session_id=self.server.session_id,
                        src_ip=self.server.src_ip,
                        username=self.server.username,
                        event_type="command",
                        command=line,
                        mitre_id=tech.technique_id if tech else None,
                        mitre_name=tech.name if tech else None,
                        output=out,
                    )
                    if self.server.event_callback:
                        self.server.event_callback(ev)

                self._prompt()
            elif char in ("\x7f", "\x08"):
                if len(self.input_buf) > 0:
                    self.input_buf = self.input_buf[:-1]
                    self.chan.write("\b \b")
            elif char == "\x03":  # Ctrl+C
                self.input_buf = ""
                self.chan.write("^C\r\n")
                self._prompt()
            else:
                self.input_buf += char
                self.chan.write(char)

def generate_host_key(key_path: str):
    """Generates an RSA host key for asyncssh if not existing."""
    if not os.path.exists(key_path):
        os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(key_path)

async def start_server(
    host: str = "0.0.0.0",
    port: int = 2222,
    log_path: str = "data/sessions.jsonl",
    key_path: str = "data/host_key",
    event_callback: Optional[Callable[[SessionEvent], None]] = None,
):
    generate_host_key(key_path)
    recorder = SessionRecorder(log_path)
    recorder.open()

    def server_factory():
        return HoneypotSSHServer(recorder, event_callback)

    def session_factory():
        return HoneypotShellSession(server_factory())

    listener = await asyncssh.create_server(
        server_factory,
        host,
        port,
        server_host_keys=[key_path],
        session_factory=lambda conn: HoneypotShellSession(conn.get_server()),
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    )
    return listener, recorder

# AsyncSSH listener and session context initialization
