"""Root conftest — restricts anyio to asyncio backend only (trio not installed)."""

import pytest


@pytest.fixture(params=["asyncio"])
def anyio_backend(request):
    return request.param
