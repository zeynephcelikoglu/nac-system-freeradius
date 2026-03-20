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
    """asyncpg connection pool mock'u üretir."""
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
    """Redis mock'u üretir."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=str(fail_count) if fail_count else None)
    redis.incr = AsyncMock(return_value=fail_count + 1)
    redis.expire = AsyncMock()
    redis.delete = AsyncMock()
    redis.ping = AsyncMock()
    return redis


def make_mac_db_mock(mac_found=True):
    """MAB testi için mac_whitelist mock'u."""
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
    """Test 1: Doğru şifreyle /auth 200 dönmeli."""
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
    """Test 2: Yanlış şifreyle /auth 401 dönmeli."""
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
    """Test 3: 5 başarısız girişten sonra /auth 429 dönmeli."""
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
    """Test 4: Whitelist'teki MAC adresi /auth 200 dönmeli."""
    app.state.db    = make_mac_db_mock(mac_found=True)
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "00:11:22:33:44:55",
            "password": "00:11:22:33:44:55"
        })

    assert res.status_code == 200


@pytest.mark.asyncio
async def test_mab_unknown_mac():
    """Test 5: Whitelist'te olmayan MAC /auth 401 dönmeli."""
    app.state.db    = make_mac_db_mock(mac_found=False)
    app.state.redis = make_redis_mock()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/auth", json={
            "username": "AA:BB:CC:DD:EE:FF",
            "password": "AA:BB:CC:DD:EE:FF"
        })

    assert res.status_code == 401