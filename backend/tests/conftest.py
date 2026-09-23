import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="sentinelforge-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SIEM_MODE"] = "disabled"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ.pop("API_KEY", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services import demo  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def api(client):
    """A client with an empty database (rule templates are kept)."""
    client.post("/api/v1/demo/reset")
    return client


@pytest.fixture
def db(client):
    with SessionLocal() as s:
        demo.reset(s)
        yield s


@pytest.fixture
def settings():
    s = get_settings()
    snapshot = s.model_copy()
    yield s
    for k in type(s).model_fields:
        setattr(s, k, getattr(snapshot, k))
