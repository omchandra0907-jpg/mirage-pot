"""In-Memory POSIX Virtual Filesystem (VFS) and Shell Emulator."""

import copy
import hashlib
import os
import posixpath
import shlex
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class VNode:
    name: str
    is_dir: bool = False
    mode: str = "rw-r--r--"
    owner: str = "root"
    group: str = "root"
    content: str = ""
    mtime: float = field(default_factory=time.time)
    children: Dict[str, "VNode"] = field(default_factory=dict)

def generate_canary_credentials(session_id: str) -> Dict[str, str]:
    """Generates traceable session-unique canary credentials."""
    token = hashlib.sha256(session_id.encode()).hexdigest()[:12]
    return {
        "env": (
            f"# Production Environment Variables (Auto-generated)\n"
            f"APP_ENV=production\n"
            f"SECRET_KEY=canary_sec_{token}_9827341\n"
            f"DATABASE_URL=postgres://app_prod:canary_db_{token}@10.0.4.12:5432/core_db\n"
            f"AWS_ACCESS_KEY_ID=AKIA{token.upper()}CANARY\n"
            f"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY_{token}\n"
            f"STRIPE_API_KEY=sk_live_{token}_canary_token_v3\n"
        ),
        "ssh_key": (
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
            f"NhAAAAAwEAAQAAAYEA0b4CANARY{token}DEADBEEFCAFE0123456789==\n"
            f"canary-trap-session-{token}@internal-bastion\n"
            f"-----END OPENSSH PRIVATE KEY-----\n"
        ),
        "aws_creds": (
            f"[default]\n"
            f"aws_access_key_id = AKIA{token.upper()}BAIT\n"
            f"aws_secret_access_key = {token}XyZaBcDeFgHiJkLmNoPqRsTuVwXyZ\n"
            f"region = us-east-1\n"
        )
    }

def create_default_vfs_tree(session_id: str) -> VNode:
    """Builds standard realistic Linux root tree with canary bait files."""
    canaries = generate_canary_credentials(session_id)
    root = VNode(name="", is_dir=True, mode="rwxr-xr-x")

    def mkdir_p(path: str) -> VNode:
        parts = [p for p in path.strip("/").split("/") if p]
        curr = root
        for part in parts:
            if part not in curr.children:
                curr.children[part] = VNode(name=part, is_dir=True, mode="rwxr-xr-x")
            curr = curr.children[part]
        return curr

    def add_file(path: str, content: str, mode: str = "rw-r--r--", owner: str = "root"):
        dpath, fname = posixpath.split(path)
        parent = mkdir_p(dpath)
        parent.children[fname] = VNode(name=fname, is_dir=False, mode=mode, owner=owner, content=content)

    # Standard POSIX directories
    for d in ["/bin", "/etc", "/home/ubuntu", "/root", "/root/.ssh", "/tmp", "/var/log", "/usr/bin"]:
        mkdir_p(d)

    # System files
    add_file("/etc/hostname", "prod-srv-edge-01\n")
    add_file("/etc/issue", "Ubuntu 22.04.4 LTS \\n \\l\n")
    add_file("/etc/passwd", (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
    ))
    add_file("/etc/shadow", (
        "root:$6$vQ9yU2K1$rVvN8B89W8V3pP7qM5xO9:19240:0:99999:7:::\n"
        "ubuntu:$6$kL81j9A0$L6zR4a4M3vO8B0W7yP9q:19240:0:99999:7:::\n"
    ), mode="r--------")

    # Honey bait files
    add_file("/root/.env", canaries["env"])
    add_file("/root/.ssh/id_rsa", canaries["ssh_key"], mode="r--------")
    add_file("/root/.ssh/authorized_keys", f"ssh-rsa AAAAB3NzaC1yc2EA... deploy@{session_id[:8]}\n")
    mkdir_p("/root/.aws")
    add_file("/root/.aws/credentials", canaries["aws_creds"])

    return root

class VirtualShell:
    """Session-isolated Linux shell interpreter."""

    def __init__(self, session_id: str, username: str = "root"):
        self.session_id = session_id
        self.username = username
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.root = create_default_vfs_tree(session_id)
        self.env = {
            "USER": username,
            "HOME": self.cwd,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
        }
        self.history: List[str] = []
        self.downloaded_payloads: List[str] = []

    def _resolve_path(self, path: str) -> str:
        """Resolves path against CWD and ensures containment within VFS root."""
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        norm = posixpath.normpath(path)
        return norm

    def _get_node(self, path: str) -> Optional[VNode]:
        norm = self._resolve_path(path)
        if norm == "/":
            return self.root
        parts = [p for p in norm.split("/") if p]
        curr = self.root
        for part in parts:
            if not curr.is_dir or part not in curr.children:
                return None
            curr = curr.children[part]
        return curr

    def execute(self, command_line: str) -> str:
        """Executes a bash-like command line with support for chaining (&&, ;) and redirection."""
        line = command_line.strip()
        if not line:
            return ""
        self.history.append(line)

        # Chained commands: handle '&&' and ';'
        if "&&" in line:
            parts = line.split("&&")
            results = []
            for part in parts:
                out = self.execute(part.strip())
                if out:
                    results.append(out)
            return "\n".join(results)
        if ";" in line:
            parts = line.split(";")
            results = []
            for part in parts:
                out = self.execute(part.strip())
                if out:
                    results.append(out)
            return "\n".join(results)

        # Handle simple output redirection: cmd > file or cmd >> file
        redirect_file = None
        append_mode = False
        if ">>" in line:
            cmd_part, file_part = line.split(">>", 1)
            line = cmd_part.strip()
            redirect_file = file_part.strip()
            append_mode = True
        elif ">" in line:
            cmd_part, file_part = line.split(">", 1)
            line = cmd_part.strip()
            redirect_file = file_part.strip()

        try:
            tokens = shlex.split(line)
        except Exception:
            tokens = line.split()

        if not tokens:
            return ""

        cmd = tokens[0]
        args = tokens[1:]

        # Dispatch command
        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler:
            output = handler(args)
        else:
            output = f"bash: {cmd}: command not found"

        if redirect_file:
            self._write_file(redirect_file, output + "\n", append=append_mode)
            return ""

        return output

    def _write_file(self, path: str, content: str, append: bool = False):
        norm = self._resolve_path(path)
        dpath, fname = posixpath.split(norm)
        parent = self._get_node(dpath)
        if not parent or not parent.is_dir:
            return
        if fname in parent.children:
            node = parent.children[fname]
            node.content = (node.content + content) if append else content
            node.mtime = time.time()
        else:
            parent.children[fname] = VNode(
                name=fname,
                is_dir=False,
                mode="rw-r--r--",
                owner=self.username,
                content=content,
            )

    # Command Handlers
    def _cmd_pwd(self, args: List[str]) -> str:
        return self.cwd

    def _cmd_whoami(self, args: List[str]) -> str:
        return self.username

    def _cmd_id(self, args: List[str]) -> str:
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)"

    def _cmd_uname(self, args: List[str]) -> str:
        if "-a" in args:
            return "Linux prod-srv-edge-01 5.15.0-105-generic #115-Ubuntu SMP Thu Mar 28 14:32:11 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
        return "Linux"

    def _cmd_hostname(self, args: List[str]) -> str:
        return "prod-srv-edge-01"

    def _cmd_cd(self, args: List[str]) -> str:
        target = args[0] if args else self.env["HOME"]
        norm = self._resolve_path(target)
        node = self._get_node(norm)
        if not node:
            return f"bash: cd: {target}: No such file or directory"
        if not node.is_dir:
            return f"bash: cd: {target}: Not a directory"
        self.cwd = norm
        return ""

    def _cmd_ls(self, args: List[str]) -> str:
        show_all = any("-a" in a for a in args)
        long_format = any("-l" in a for a in args)
        target = "."
        for a in args:
            if not a.startswith("-"):
                target = a
                break

        node = self._get_node(target)
        if not node:
            return f"ls: cannot access '{target}': No such file or directory"

        if not node.is_dir:
            return node.name

        entries = sorted(node.children.keys())
        if not show_all:
            entries = [e for e in entries if not e.startswith(".")]

        if long_format:
            lines = [f"total {len(entries) * 4}"]
            for e in entries:
                child = node.children[e]
                type_char = "d" if child.is_dir else "-"
                mode = type_char + child.mode
                size = len(child.content) if not child.is_dir else 4096
                lines.append(f"{mode} 1 {child.owner} {child.group} {size:6d} Nov 24 12:00 {e}")
            return "\n".join(lines)
        return "  ".join(entries)

    def _cmd_cat(self, args: List[str]) -> str:
        if not args:
            return ""
        out = []
        for target in args:
            node = self._get_node(target)
            if not node:
                out.append(f"cat: {target}: No such file or directory")
            elif node.is_dir:
                out.append(f"cat: {target}: Is a directory")
            else:
                out.append(node.content.rstrip("\n"))
        return "\n".join(out)

    def _cmd_echo(self, args: List[str]) -> str:
        return " ".join(args)

    def _cmd_touch(self, args: List[str]) -> str:
        for target in args:
            self._write_file(target, "", append=True)
        return ""

    def _cmd_mkdir(self, args: List[str]) -> str:
        for target in args:
            if target.startswith("-"):
                continue
            norm = self._resolve_path(target)
            dpath, fname = posixpath.split(norm)
            parent = self._get_node(dpath)
            if parent and parent.is_dir and fname not in parent.children:
                parent.children[fname] = VNode(name=fname, is_dir=True, mode="rwxr-xr-x", owner=self.username)
        return ""

    def _cmd_rm(self, args: List[str]) -> str:
        for target in args:
            if target.startswith("-"):
                continue
            norm = self._resolve_path(target)
            if norm == "/":
                return "rm: it is dangerous to operate recursively on '/'"
            dpath, fname = posixpath.split(norm)
            parent = self._get_node(dpath)
            if parent and fname in parent.children:
                del parent.children[fname]
        return ""

    def _cmd_ps(self, args: List[str]) -> str:
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.2 168432 11840 ?        Ss   10:00   0:01 /sbin/init\n"
            "root       342  0.0  0.1  72304  8192 ?        Ss   10:00   0:00 /lib/systemd/systemd-journald\n"
            "root       512  0.0  0.1  15420  5120 ?        Ss   10:00   0:00 /usr/sbin/sshd -D\n"
            "root      1204  0.0  0.2  18240  7820 pts/0    Ss   12:14   0:00 -bash\n"
            "root      1350  0.0  0.1  21400  3200 pts/0    R+   12:15   0:00 ps aux\n"
        )

    def _cmd_curl(self, args: List[str]) -> str:
        """Fake curl: records downloaded payload URL and returns realistic output without egress."""
        url = args[-1] if args else "http://attacker.c2/payload.sh"
        self.downloaded_payloads.append(url)
        # Fake script content
        fake_content = "#!/bin/sh\n# Exploit payload\necho 'Mining initialized...'\n"
        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 < len(args):
                self._write_file(args[idx + 1], fake_content)
                return ""
        if "-O" in args:
            fname = posixpath.split(url.split("?")[0])[1] or "downloaded"
            self._write_file(fname, fake_content)
            return ""
        return fake_content

    def _cmd_wget(self, args: List[str]) -> str:
        url = args[-1] if args else "http://attacker.c2/bot"
        self.downloaded_payloads.append(url)
        fname = posixpath.split(url.split("?")[0])[1] or "index.html"
        self._write_file(fname, "#!/bin/sh\necho 'Agent active'\n")
        return (
            f"--2026-11-24 12:15:30--  {url}\n"
            f"Resolving attacker.c2... 198.51.100.44\n"
            f"Connecting to attacker.c2|198.51.100.44|:80... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Length: 2048 (2.0K) [application/x-sh]\n"
            f"Saving to: '{fname}'\n\n"
            f"{fname}               100%[===================>]   2.00K  --.-KB/s    in 0.002s\n\n"
            f"2026-11-24 12:15:30 (1.12 MB/s) - '{fname}' saved [2048/2048]"
        )

    def _cmd_history(self, args: List[str]) -> str:
        return "\n".join(f"{i+1:5d}  {cmd}" for i, cmd in enumerate(self.history))

    def _cmd_exit(self, args: List[str]) -> str:
        return "logout"

# POSIX path normalization and directory resolver

# In-memory filesystem hierarchy clone

# Shlex command router and pipeline tokenizer

# Directory navigation handlers

# In-memory file modification and redirection
