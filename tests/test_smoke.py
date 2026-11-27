from importlib.metadata import version

import egressguard


def test_version() -> None:
    assert egressguard.__version__ == "0.3.1"
    assert version("egressguard") == egressguard.__version__  # pyproject and package agree
