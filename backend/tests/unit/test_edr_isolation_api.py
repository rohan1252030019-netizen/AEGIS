"""
Unit tests for EDR Host Isolation API endpoints (FR-09).
"""

from __future__ import annotations

import uuid
from datetime import datetime
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Client
from app.models.endpoint_agent import EndpointAgent, AgentStatus
from tests.conftest import api_key_headers


@pytest.fixture
async def seeded_agent(test_client_a: Client) -> EndpointAgent:
    from app.database import async_session
    async with async_session() as db:
        existing_client = await db.get(Client, test_client_a.id)
        if not existing_client:
            c = Client(
                id=test_client_a.id,
                name="Test Tenant A",
                slug=f"tenant-a-{uuid.uuid4().hex[:6]}",
                api_key=test_client_a.api_key,
            )
            db.add(c)
            await db.commit()

        agent = EndpointAgent(
            id=f"agent-{uuid.uuid4().hex[:8]}",
            client_id=test_client_a.id,
            hostname="WIN-ENDPOINT-01",
            os_info="Windows 11 Pro",
            ip_address="192.168.1.150",
            agent_version="1.0.0",
            status=AgentStatus.online,
            config={},
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        return agent


class TestEdrHostIsolationApi:
    @pytest.mark.asyncio
    async def test_isolate_host_endpoint_success(
        self, client: AsyncClient, test_client_a: Client, seeded_agent: EndpointAgent
    ):
        headers = api_key_headers(test_client_a)
        payload = {
            "reason": "Suspected ransomware activity",
            "lease_seconds": 600,
            "confirm": True,
        }

        resp = await client.post(
            f"/api/v1/edr/hosts/{seeded_agent.id}/isolate",
            json=payload,
            headers=headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True
        assert data["agent_id"] == seeded_agent.id
        assert data["status"] == "ISOLATING"
        assert data["lease_seconds"] == 600

    @pytest.mark.asyncio
    async def test_isolate_host_requires_confirmation(
        self, client: AsyncClient, test_client_a: Client, seeded_agent: EndpointAgent
    ):
        headers = api_key_headers(test_client_a)
        payload = {
            "reason": "Test without confirmation",
            "confirm": False,
        }

        resp = await client.post(
            f"/api/v1/edr/hosts/{seeded_agent.id}/isolate",
            json=payload,
            headers=headers,
        )

        assert resp.status_code == 400
        assert "Confirmation required" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_unisolate_host_endpoint_success(
        self, client: AsyncClient, test_client_a: Client, seeded_agent: EndpointAgent
    ):
        headers = api_key_headers(test_client_a)
        payload = {
            "reason": "Host remediated and cleared",
        }

        resp = await client.post(
            f"/api/v1/edr/hosts/{seeded_agent.id}/unisolate",
            json=payload,
            headers=headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True
        assert data["status"] == "RESTORING"

    @pytest.mark.asyncio
    async def test_get_isolation_status(
        self, client: AsyncClient, test_client_a: Client, seeded_agent: EndpointAgent
    ):
        headers = api_key_headers(test_client_a)
        resp = await client.get(
            f"/api/v1/edr/hosts/{seeded_agent.id}/isolation-status",
            headers=headers,
        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["agent_id"] == seeded_agent.id
        assert "isolation" in data
        assert "state" in data["isolation"]
