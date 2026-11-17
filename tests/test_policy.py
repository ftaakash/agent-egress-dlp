"""F1: policy file."""

from pathlib import Path

import pytest

from egressguard.policy import DEFAULT_ACTIONS, RULES, Policy, PolicyError, find_policy, load_policy


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / ".egressguard.yml"
    p.write_text(text, encoding="utf-8")
    return p


def test_acceptance_policy_overrides_and_defaults(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        """
rules:
  email: block
allow:
  - host: api.internal.test
    rules: [registered_secret]
""",
    )
    pol = load_policy(p)
    assert pol.actions["email"] == "block"
    # every other rule keeps its default
    for rule in RULES:
        if rule != "email":
            assert pol.actions[rule] == DEFAULT_ACTIONS[rule]
    assert pol.allowed("api.internal.test", "registered_secret")
    assert not pol.allowed("api.internal.test", "aws_access_key")
    assert not pol.allowed("evil.example.com", "registered_secret")
    # passthrough defaults are kept when the file does not set them
    assert pol.is_passthrough("api.anthropic.com")


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("rules:\n  credit_card: block\n", "credit_card"),
        ("rules:\n  email: drop\n", "drop"),
        ("colour: blue\n", "colour"),
        ("allow:\n  - host: x.test\n    rules: [nope]\n", "nope"),
        ("allow:\n  - rules: [email]\n", "host"),
        ("passthrough_hosts: api.anthropic.com\n", "passthrough_hosts"),
        ("- just\n- a list\n", "mapping"),
        ("rules: [unclosed\n", "YAML"),
    ],
)
def test_bad_policy_names_the_problem(tmp_path: Path, text: str, needle: str) -> None:
    with pytest.raises(PolicyError) as e:
        load_policy(write(tmp_path, text))
    assert needle in str(e.value)


def test_defaults_without_file() -> None:
    pol = Policy.default()
    assert pol.actions == DEFAULT_ACTIONS
    assert pol.actions["aws_access_key"] == "block"
    assert pol.actions["email"] == "redact"
    assert pol.env_files == (".env",)
    assert pol.scan_environment is True


def test_empty_file_is_defaults(tmp_path: Path) -> None:
    assert load_policy(write(tmp_path, "")) == Policy.default()


def test_passthrough_matching(tmp_path: Path) -> None:
    pol = load_policy(write(tmp_path, "passthrough_hosts: [api.model.test, '*.llm.test']\n"))
    assert pol.is_passthrough("api.model.test")
    assert pol.is_passthrough("API.MODEL.TEST")
    assert pol.is_passthrough("eu.llm.test")
    assert not pol.is_passthrough("llm.test.evil.com")
    assert not pol.is_passthrough("api.anthropic.com")  # the list replaces the defaults
    assert pol.ignore_hosts_regex() == r"^(?:api\.model\.test|[^.:]+\.llm\.test):\d+$"


def test_allow_wildcard(tmp_path: Path) -> None:
    pol = load_policy(write(tmp_path, "allow:\n  - host: '*.corp.test'\n    rules: [email, git_email]\n"))
    assert pol.allowed("git.corp.test", "email")
    assert not pol.allowed("corp.test.evil", "email")


def test_find_policy(tmp_path: Path) -> None:
    assert find_policy(tmp_path) is None
    p = write(tmp_path, "")
    assert find_policy(tmp_path) == p


def test_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yml")


def test_weakened_lists_loosened_rules_and_allowlist(tmp_path: Path) -> None:
    pol = load_policy(
        write(
            tmp_path,
            "rules:\n  aws_access_key: log\n  email: block\n"
            "allow:\n  - host: '*.corp.test'\n    rules: [registered_secret]\n",
        )
    )
    weak = pol.weakened()
    assert "aws_access_key: log (default block)" in weak
    assert "allow *.corp.test: registered_secret" in weak
    assert not any("email" in w for w in weak)  # stricter than the default is not a weakening
    assert Policy.default().weakened() == []
