import pytest

@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    monkeypatch.setenv("ARTIPHISHELL_FAIL_EARLY", "1")