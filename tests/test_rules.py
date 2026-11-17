"""F2: content rules.

Token-shaped test values are built at runtime so that no literal key-format string sits in the repository
(secret scanners would flag it). All values are fake.
"""

from pathlib import Path

import pytest

from egressguard.rules import Scanner, redact
from egressguard.secrets import env_file_values, environment_values

AWS = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example key
GH = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"  # 36 chars after the prefix
ANT = "sk-" + "ant-api03-" + "x" * 40
OAI = "sk-" + "proj-" + "Y" * 40
STRIPE = "sk" + "_test_" + "Z9" * 12
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----"
ENV_SECRET = "s3cr3t-value-from-dotenv"


def scanner() -> Scanner:
    return Scanner(registered=[ENV_SECRET], git_email="dev.user@example.com", os_username="jdoe-laptop")


def test_acceptance_request_findings() -> None:
    found = scanner().scan_request(
        url=f"https://tools.example.test/search?q={ENV_SECRET}&by=jdoe-laptop",
        headers=[("Authorization", f"token {GH}"), ("User-Agent", "agent/1.0 (dev.user@example.com)")],
        body=f"AWS_ACCESS_KEY_ID={AWS}\n",
    )
    got = {(f.rule, f.where) for f in found}
    assert got == {
        ("registered_secret", "url"),
        ("os_username", "url"),
        ("github_token", "header:Authorization"),
        ("git_email", "header:User-Agent"),
        ("aws_access_key", "body"),
    }


def test_acceptance_clean_request() -> None:
    found = scanner().scan_request(
        url="https://docs.example.test/page?q=how+to+parse+json",
        headers=[("User-Agent", "agent/1.0"), ("Accept", "text/html")],
        body='{"query": "python list comprehension", "n": 3}',
    )
    assert found == []


@pytest.mark.parametrize(
    ("value", "rule"),
    [(AWS, "aws_access_key"), (GH, "github_token"), (ANT, "anthropic_key"), (OAI, "openai_key")]
    + [(STRIPE, "stripe_key"), (PEM, "private_key"), ("someone@example.org", "email")],
)
def test_each_format(value: str, rule: str) -> None:
    found = Scanner().scan(f"before {value} after", "body")
    assert [f.rule for f in found] == [rule]
    assert found[0].value == value


def test_anthropic_key_is_not_also_openai() -> None:
    assert [f.rule for f in Scanner().scan(ANT, "body")] == ["anthropic_key"]


def test_github_fine_grained_pat() -> None:
    pat = "github_" + "pat_" + "11ABCDEFG" + "0" * 13 + "_" + "q" * 59
    assert [f.rule for f in Scanner().scan(pat, "body")] == ["github_token"]


def test_registered_secret_url_encoded() -> None:
    s = Scanner(registered=["p@ss word/with&chars"])
    found = s.scan("https://x.test/?pw=p%40ss%20word%2Fwith%26chars", "url")
    assert [f.rule for f in found] == ["registered_secret"]
    found = s.scan("pw=p%40ss+word%2Fwith%26chars", "body")
    assert [f.rule for f in found] == ["registered_secret"]


def test_email_url_encoded() -> None:
    assert [f.rule for f in Scanner().scan("u=dev.user%40example.com", "url")] == ["email"]


def test_git_email_wins_over_email_and_is_case_insensitive() -> None:
    found = Scanner(git_email="Dev.User@Example.com").scan("x dev.user@example.com y", "body")
    assert [f.rule for f in found] == ["git_email"]


def test_username_word_boundary_and_generic_names() -> None:
    s = Scanner(os_username="jdoe")
    assert [f.rule for f in s.scan(r"C:\Users\jdoe\project", "body")] == ["os_username"]
    assert s.scan("jdoes and xjdoe", "body") == []
    assert Scanner(os_username="Administrator").scan("C:/Users/Administrator", "body") == []
    assert Scanner(os_username="abc").scan("abc", "body") == []  # too short to be identifying


def test_short_registered_values_are_ignored() -> None:
    assert Scanner(registered=["1234", ""]).scan("pin 1234", "body") == []


def test_redact_replaces_every_finding() -> None:
    s = scanner()
    text = f"key={AWS} mail=dev.user@example.com other=a@b.example"
    out = redact(text, s.scan(text, "body"))
    assert out == "key=[REDACTED:aws_access_key] mail=[REDACTED:git_email] other=[REDACTED:email]"


def test_env_file_values(tmp_path: Path) -> None:
    p = tmp_path / ".env"
    p.write_text(
        "# comment\nexport API_TOKEN='quoted-value-123'\nDB_PASSWORD=\"dq-value-456\"\n"
        "EMPTY=\nPLAIN=plain-value-789 # trailing comment\nnot a line\nSHORT=abc\n",
        encoding="utf-8",
    )
    assert env_file_values(p) == ["quoted-value-123", "dq-value-456", "plain-value-789"]
    assert env_file_values(tmp_path / "missing.env") == []


def test_environment_values_only_secret_names() -> None:
    env = {
        "GITHUB_TOKEN": "tok-1234567890",
        "AWS_SECRET_ACCESS_KEY": "aws-secret-12345",
        "ANTHROPIC_API_KEY": "ant-key-123456789",
        "DB_PASSWORD": "pw-12345678",
        "PATH": "/usr/bin:/bin",
        "PWD": "/home/user/project",
        "KEYBOARD": "us-international",
        "MY_TOKEN": "short",
        "EGRESSGUARD_SESSION": "/tmp/session.json",
    }
    assert sorted(environment_values(env)) == sorted(
        ["tok-1234567890", "aws-secret-12345", "ant-key-123456789", "pw-12345678"]
    )


def test_environment_values_skip_paths_and_ids() -> None:
    env = {
        "SSH_KEY_PATH": "/home/user/.ssh/id_ed25519",
        "GPG_KEY_ID": "ABCDEF1234567890",
        "TOKEN_FILE": "/run/secrets/token",
        "SSH_AUTH_SOCK": "/tmp/ssh-agent.sock",
        "STRIPE_KEY": "stripe-value-123456",
    }
    assert environment_values(env) == ["stripe-value-123456"]
