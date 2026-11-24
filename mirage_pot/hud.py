"""Live Rich Terminal HUD and Session Replay Player."""

import json
import os
import sys
import time

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .recorder import SessionEvent

console = Console()


class AttackHUD:
    def __init__(self):
        self.events: list[SessionEvent] = []
        self.active_sessions: dict[str, dict] = {}
        self.mitre_stats: dict[str, int] = {}
        self.total_attacks = 0

    def add_event(self, ev: SessionEvent):
        self.events.append(ev)
        if len(self.events) > 15:
            self.events.pop(0)

        # Update stats
        if ev.session_id not in self.active_sessions:
            self.active_sessions[ev.session_id] = {
                "ip": ev.src_ip,
                "user": ev.username,
                "cmds": 0,
                "last_seen": time.time(),
            }
        self.active_sessions[ev.session_id]["cmds"] += 1
        self.active_sessions[ev.session_id]["last_seen"] = time.time()

        if ev.mitre_id:
            tag = f"{ev.mitre_id} ({ev.mitre_name})"
            self.mitre_stats[tag] = self.mitre_stats.get(tag, 0) + 1
            self.total_attacks += 1

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(
            Layout(name="events", ratio=2),
            Layout(name="sidebar", ratio=1),
        )

        # Header
        header_text = Text(
            f" 🛡️  MIRAGE-POT  |  Adaptive Deception Honeypot & Attack HUD  |  Events: {len(self.events)}  Attacks: {self.total_attacks}",
            style="bold cyan on #1a1b26",
            justify="center",
        )
        layout["header"].update(Panel(header_text, style="cyan"))

        # Events Table
        tbl = Table(title="🚨 Real-Time Command Telemetry Stream", expand=True, border_style="dim")
        tbl.add_column("Time", style="dim", width=10)
        tbl.add_column("IP", style="yellow", width=14)
        tbl.add_column("User", style="green", width=8)
        tbl.add_column("Command", style="bold white")
        tbl.add_column("MITRE ATT&CK", style="bold red", width=24)

        for ev in reversed(self.events):
            t_str = time.strftime("%H:%M:%S", time.localtime(ev.timestamp_ms / 1000.0))
            mitre_disp = f"[{ev.mitre_id}] {ev.mitre_name}" if ev.mitre_id else "-"
            cmd_disp = (ev.command[:35] + "…") if len(ev.command) > 38 else ev.command
            tbl.add_row(t_str, ev.src_ip, ev.username, cmd_disp, mitre_disp)

        layout["events"].update(Panel(tbl, border_style="blue"))

        # Sidebar: Sessions and MITRE breakdown
        side_table = Table(title="📊 MITRE ATT&CK Distribution", expand=True, border_style="dim")
        side_table.add_column("Technique", style="red")
        side_table.add_column("Count", justify="right", style="bold yellow")

        sorted_mitre = sorted(self.mitre_stats.items(), key=lambda x: x[1], reverse=True)[:6]
        for m_name, count in sorted_mitre:
            side_table.add_row(m_name[:22], str(count))

        sess_table = Table(title="🎯 Active Sessions", expand=True, border_style="dim")
        sess_table.add_column("SessID", style="cyan")
        sess_table.add_column("Source IP", style="yellow")
        sess_table.add_column("Cmds", justify="right")

        for sid, info in list(self.active_sessions.items())[-4:]:
            sess_table.add_row(sid[:8], info["ip"], str(info["cmds"]))

        side_layout = Layout()
        side_layout.split_column(
            Layout(Panel(side_table, border_style="magenta")),
            Layout(Panel(sess_table, border_style="green")),
        )
        layout["sidebar"].update(side_layout)

        # Footer
        footer_text = Text(
            " Canaries Active: [.env, id_rsa, aws/credentials] | Status: MONITORING (0.0.0.0:2222) | Press Ctrl+C to stop",
            style="dim white",
            justify="center",
        )
        layout["footer"].update(Panel(footer_text, border_style="dim"))
        return layout


def replay_session(log_path: str, speed: float = 1.0):
    """Replays captured JSONL attacker session with simulated typing cadence."""
    if not os.path.exists(log_path):
        console.print(f"[red]Error: Session log file not found: {log_path}[/red]")
        sys.exit(1)

    console.print(
        f"[bold cyan]▶ Replaying attacker session:[/bold cyan] {log_path} (Speed: {speed}x)"
    )
    time.sleep(1.0)

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            delay = min(data.get("delay_ms", 500) / 1000.0 / speed, 1.5)
            time.sleep(delay)

            ev_type = data.get("event_type")
            cmd = data.get("command", "")
            mitre_id = data.get("mitre_id")
            mitre_name = data.get("mitre_name")
            output = data.get("output", "")
            user = data.get("username", "root")
            src_ip = data.get("src_ip", "127.0.0.1")

            if ev_type == "auth_attempt":
                console.print(f"[yellow]⚡ Auth attempt from {src_ip}: {cmd}[/yellow]")
            elif ev_type == "auth_success":
                console.print(f"[bold green]✓ Session established: {user}@{src_ip}[/bold green]\n")
            elif ev_type == "command":
                mitre_badge = (
                    f"[bold white on red] {mitre_id}: {mitre_name} [/bold white on red] "
                    if mitre_id
                    else ""
                )
                console.print(
                    f"[bold cyan]{user}@prod-srv-edge-01:~#[/bold cyan] {cmd}  {mitre_badge}"
                )
                if output:
                    console.print(f"[dim]{output}[/dim]")
