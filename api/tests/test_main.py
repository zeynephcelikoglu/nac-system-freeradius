import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import app


# Mock DB and Redis Setup
def make_db_mock(attribute="Bcrypt-Password", value=None):
    """Create an asyncpg connection pool mock."""
    import bcrypt as _bcrypt
    if value is None:
        value = _bcrypt.hashpw(b"123456", _bcrypt.gensalt()).decode()

    row = MagicMock()
    row.__getitem__ = lambda self, key: {"attribute": attribute, "value": value}[key]

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row)
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)

    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=conn)
    pool.close = AsyncMock()
    return pool


def make_redis_mock(fail_count=0):
    """Create a Redis mock."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=str(fail_count) if fail_count else None)
    redis.incr = AsyncMock(return_value=fail_count + 1)
    redis.expire = AsyncMock()
    redis.delete = AsyncMock()
    redis.ping = AsyncMock()
    return redis


def make_mac_db_mock(mac_found=True):
    """Create a mac_whitelist mock for MAB tests."""
    row = MagicMock() if mac_found else None

    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row)
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)

    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=conn)
    pool.close = AsyncMock()
    return pool


# Test Cases
@pytest.mark.asyncio
async def test_auth_success():
    """Test 1: /auth should return 200 with the correct password."""
    app.state.db    = make_db_mock()
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "zeynep",
            "password": "123456"
        })

    assert res.status_code == 200


@pytest.mark.asyncio
async def test_auth_wrong_password():
    """Test 2: /auth should return 401 with the wrong password."""
    app.state.db    = make_db_mock()
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "zeynep",
            "password": "yanlis_sifre"
        })

    assert res.status_code == 401


@pytest.mark.asyncio
async def test_rate_limit():
    """Test 3: /auth should return 429 after 5 failed attempts."""
    app.state.db    = make_db_mock()
    app.state.redis = make_redis_mock(fail_count=5)  

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "zeynep",
            "password": "herhangi"
        })

    assert res.status_code == 429


@pytest.mark.asyncio
async def test_mab_known_mac():
    """Test 4: /auth should return 200 for a whitelisted MAC address."""
    app.state.db    = make_mac_db_mock(mac_found=True)
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "switch-port-1",
            "password": "ignored",
            "Calling-Station-Id": "00:11:22:33:44:55"
        })

    assert res.status_code == 200


@pytest.mark.asyncio
async def test_mab_unknown_mac():
    """Test 5: /auth should return 401 for a MAC address not in the whitelist."""
    app.state.db    = make_mac_db_mock(mac_found=False)
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "switch-port-2",
            "password": "ignored",
            "Calling-Station-Id": "AA:BB:CC:DD:EE:FF"
        })

    assert res.status_code == 401


@pytest.mark.asyncio
async def test_mab_known_mac_without_username_mac():
    """Test 6: MAB should also accept the MAC from Calling-Station-Id."""
    app.state.db    = make_mac_db_mock(mac_found=True)
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "device-login",
            "password": "device-login",
            "Calling-Station-Id": "00-11-22-33-44-55"
        })

    assert res.status_code == 200