import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from app.services.osv_service import query_osv_for_package, extract_cve_id, extract_references, OSV_CACHE

@pytest.fixture(autouse=True)
def clear_osv_cache():
    OSV_CACHE.clear()
    yield
    OSV_CACHE.clear()

def test_extract_cve_id():
    raw_1 = {"id": "CVE-2023-1234", "aliases": ["GHSA-xxxx"]}
    assert extract_cve_id(raw_1) == "CVE-2023-1234"

    raw_2 = {"id": "GHSA-xxxx", "aliases": ["CVE-2024-5678"]}
    assert extract_cve_id(raw_2) == "CVE-2024-5678"

    raw_3 = {"id": "GHSA-xxxx", "aliases": []}
    assert extract_cve_id(raw_3) is None

@pytest.mark.asyncio
async def test_query_osv_hit():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-9hjg-9r4m-mvj7",
                "summary": "Mock vulnerability",
                "aliases": ["CVE-2024-35195"]
            }
        ]
    }

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.return_value = mock_response

    results = await query_osv_for_package(mock_client, "requests-test-pkg", "2.25.1")
    assert len(results) == 1
    assert results[0]["id"] == "GHSA-9hjg-9r4m-mvj7"

@pytest.mark.asyncio
async def test_query_osv_no_hit():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.return_value = mock_response

    results = await query_osv_for_package(mock_client, "safe-pkg-xyz", "1.0.0")
    assert len(results) == 0
