import asyncio
import sys
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase
import aiobastion
import tests

class TestEPV(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

    async def test_logoff(self):
        await self.vault.logoff()
        self.assertFalse(await self.vault.check_token())
        # self.fail()

    async def test_login_aim(self):
        await self.vault.logoff()
        self.assertFalse(await self.vault.check_token())
        self.vault = aiobastion.EPV('../../confs/config_aim_hprod_bsa.yml')
        await self.vault.login()
        self.assertTrue(await self.vault.check_token())
        await self.vault.close_session()


    async def test_check_token(self):
        self.assertTrue(await self.vault.check_token())

    async def test_login(self):
        self.assertTrue(await self.vault.check_token())

    def test_get_url(self):
        addr, head = self.vault.get_url("Accounts")
        self.assertIn("PasswordVault", addr)
        self.assertIn("Authorization", head)
        # self.fail()

    def test_to_json(self):
        serialized = self.vault.to_json()
        self.assertIsInstance(serialized,dict)
        # self.fail()

    async def test_handle_request(self):
        ret = await self.vault.handle_request(
            "get",
            "WebServices/PIMServices.svc/User",
            filter_func=lambda x: x['AgentUser'])

        self.assertFalse(ret)

if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    unittest.main()
