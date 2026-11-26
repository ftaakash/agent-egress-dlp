from importlib.metadata import version

import egressguard


def test_version() -> None:
    assert egressguard.__version__ == "0.2.0"
    assert version("egressguard") == egressguard.__version__  # pyproject and package agree
