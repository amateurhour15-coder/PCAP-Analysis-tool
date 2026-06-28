"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
import tempfile
from database.db_manager import DatabaseManager
from database.schema import init_database


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        init_database(db_path)
        yield DatabaseManager(db_path)
