from unittest.mock import AsyncMock, MagicMock

import pytest

import aiobastion
from aiobastion import EPV

@pytest.fixture
def mock_epv():
    """Fixture pour créer un client CyberArk mocké"""

    mock_epv = MagicMock(spec=EPV)

    # === ACCOUNT ===
    mock_epv.account = MagicMock()
    mock_epv.account.create_account = AsyncMock()
    mock_epv.account.add_account_to_safe = AsyncMock()
    mock_epv.account.get_account = AsyncMock()
    mock_epv.account.update_account = AsyncMock()
    mock_epv.account.delete_account = AsyncMock()
    mock_epv.account.search_account_by = AsyncMock()
    mock_epv.account.get_password = AsyncMock()
    mock_epv.account.link_account = AsyncMock()

    return mock_epv

    # Rendre toutes les méthodes async
    mock_client.account.add_account_to_safe = AsyncMock()
    mock_client.get_account = AsyncMock()
    mock_client.get_privileged_account_id = AsyncMock()
    mock_client.link_reconciliation_account = AsyncMock()

    return mock_client
    config = {
        "api_host": "pvwa.mycompany.com",
    }
    client = aiobastion.EPV(serialized=config)
    client.epv = AsyncMock()
    return client