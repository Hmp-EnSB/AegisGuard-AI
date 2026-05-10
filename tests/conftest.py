"""
Pytest configuration — loads models before any test runs.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

@pytest.fixture(scope="session", autouse=True)
def load_models():
    """Load all pkl models once before the test session starts."""
    from api.core.model_loader import load_all_models
    load_all_models()
    yield
