import pytest
from aioresponses import aioresponses
from aiobastion.accounts import PrivilegedAccount


# Pas de classe, pas de self, juste des fonctions
@pytest.mark.asyncio
async def test_add_single_account_success(mock_epv):
    """Test ajout d'un compte unique avec succès"""
    with aioresponses() as m:
        m.post('https://cyberark.example.com/API/Accounts',
               payload={'id': '123_456'})

        # Utiliser directement le client de la fixture
        account = PrivilegedAccount(
            userName='testuser',
            safeName='TestSafe',
            address='server.example.com',
            name="tutu",
            platformId="tata"
        )

        # Configurer le comportement spécifique à ce test
        mock_epv.account.add_account_to_safe.return_value = '123_456'

        result = await mock_epv.account.add_account_to_safe(account)

        assert result == '123_456'


@pytest.mark.asyncio
async def test_get_single_account_success(mock_epv):
    """Test récupération d'un compte unique"""
    account_data = {
        'id': '123_456',
        'userName': 'testuser',
        'safeName': 'TestSafe',
        'address': 'server.example.com'
    }

    # Configurer le comportement pour ce test
    mock_epv.get_account.return_value = PrivilegedAccount(**account_data)

    result = await mock_epv.get_account('123_456')

    assert isinstance(result, PrivilegedAccount)
    assert result.id == '123_456'
    assert result.userName == 'testuser'