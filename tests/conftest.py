import os
import tempfile

import pytest

_test_data = tempfile.TemporaryDirectory(prefix="secfile-tests-")
os.environ["SECFILE_DATA_DIR"] = _test_data.name
os.environ["SECFILE_STORAGE_DIR"] = os.path.join(_test_data.name, "encrypted")

from core.db import Base, engine  # noqa: E402
from src.web import main, sessions  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_database():
    sessions.clear_cached_keys()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    main._preauth.clear()
    main._attempts.clear()
    yield
    sessions.clear_cached_keys()
