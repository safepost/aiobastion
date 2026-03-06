import random
from typing import List, Union

import pytest

from aiobastion import EPV
from aiobastion.accounts import PrivilegedAccount
import tests

vault = EPV(tests.CONFIG)
test_safe = "sample-it-dept"
privileged = PrivilegedAccount("test_account", "platform", "testSafe", address="176.171.20.224", id="78_222")
create_me = PrivilegedAccount("test_account", "UnixSSH", "sample-it-dept", address="176.171.220.224", userName="admin")
create_me2 = PrivilegedAccount("test_account2", "UnixSSH", "sample-it-dept", address="176.171.220.225",
                               userName="admin")
create_me3 = PrivilegedAccount("test_account3", "UnixSSH", "sample-it-dept", address="176.171.220.226",
                               userName="admin")
admin = PrivilegedAccount("admin", "UnixSSH", "sample-it-dept", address="222.192.113.246", userName="admin")
recon = PrivilegedAccount("recon", "UnixSSH", "sample-it-dept", address="222.192.113.246", userName="recon")


@pytest.mark.asyncio
async def get_random_account(n=1, **kwargs) -> Union[PrivilegedAccount ,List[PrivilegedAccount]]:
    async with vault:
        accounts = await vault.account.search_account_by(
            safe=test_safe, **kwargs
        )
    assert len(accounts) >= 1
    if n == 1:
        return random.choice(accounts)
    else:
        return random.choices(accounts, k=n)

# @pytest.mark.asyncio
# async def test_my_async_function():
#    result = await my_async_function()
#    assert result == expected

@pytest.mark.asyncio
async def test_search_account_by():
    async with vault:
        account = await get_random_account()
        acc = account.to_json()

        s = await vault.account.search_account_by(username=account.userName)
        k = [ac.to_json() for ac in s]
        assert acc in k

        s = await vault.account.search_account_by(address=account.address)
        k = [ac.to_json() for ac in s]
        assert acc in k

        s = await vault.account.search_account_by(safe=account.safeName)
        k = [ac.to_json() for ac in s]
        assert acc in k

        s = await vault.account.search_account_by(platform=account.platformId)
        k = [ac.to_json() for ac in s]
        assert acc in k

        s = await vault.account.search_account_by(f"{account.platformId} {account.userName}")
        k = [ac.to_json() for ac in s]
        assert acc in k
