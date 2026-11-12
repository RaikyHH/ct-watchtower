"""Shared test guards."""

import pathlib
import shutil
import socket

import pytest

from ctwatchtower.config import settings

_connect = socket.socket.connect
_LOCAL = {"127.0.0.1", "::1", "localhost", ""}


@pytest.fixture(autouse=True)
def _no_api_token_from_the_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # `Settings` reads `.env`. The quickstart says `cp .env.example .env`, and anyone
    # who puts an API_TOKEN in there would otherwise get a 401 in every test file that
    # builds an app. Tests that need the token set it themselves; their monkeypatch
    # runs afterwards.
    monkeypatch.setattr(settings, "api_token", None)


@pytest.fixture(autouse=True)
def _no_real_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test ever reaches a real service. Not through a forgotten stub either.

    Registries, WHOIS servers and DNS resolvers allow single queries, not automated
    bulk ones (§16). A test suite that touches them is exactly that. Loopback stays
    allowed so local fakes keep working.
    """

    def guard(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else ""
        if host not in _LOCAL:
            raise OSError(
                f"test run: access to {host} blocked, tests do not query real services")
        return _connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guard)

REPO_RULES = pathlib.Path(__file__).resolve().parents[1] / "rules"


def copy_rule_base(target: pathlib.Path) -> pathlib.Path:
    """Copy only the bundled parts of `rules/`, no tenants.

    Anyone using the platform has productive rulesets under `rules/` (excluded via
    `.gitignore`, §14.5). The suite must see none of them: otherwise its result
    depends on which tenants somebody has created locally.
    """
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_RULES / "_template.yaml", target / "_template.yaml")
    for subdir in ("common", "examples"):
        source = REPO_RULES / subdir
        if source.is_dir():
            shutil.copytree(source, target / subdir, dirs_exist_ok=True)
    return target
