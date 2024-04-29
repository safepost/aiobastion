import asyncio
import os
import unittest
from unittest import IsolatedAsyncioTestCase
import aiobastion
import tests
from aiobastion import CyberarkException


class TestEPV(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.custom_linked_acounts = {
            "account": {
                "reconcile_account_index": 1,
                "logon_account_index": 3
            }
        }

    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        try:
            await self.vault.logoff()
        except:
            # test_logoff 
            pass

    def test_default_linked_accounts_from_yml(self):
        vault = aiobastion.EPV(tests.CONFIG)
        self.assertEqual(2, vault.account.logon_account_index)
        self.assertEqual(3, vault.account.reconcile_account_index)

    def test_default_linked_accounts_from_obj(self):
        vault = aiobastion.EPV(serialized={})
        self.assertEqual(2, vault.account.logon_account_index)
        self.assertEqual(3, vault.account.reconcile_account_index)

    def test_custom_linked_accounts_from_yml(self):
        vault = aiobastion.EPV("test_data/custom_config.yml")
        self.assertEqual(3, vault.account.logon_account_index)
        self.assertEqual(1, vault.account.reconcile_account_index)

    def test_custom_linked_accounts_from_obj(self):
        vault = aiobastion.EPV(serialized=self.custom_linked_acounts)
        self.assertEqual(3, vault.account.logon_account_index)
        self.assertEqual(1, vault.account.reconcile_account_index)

    async def test_logoff(self):
        await self.vault.logoff()
        self.assertFalse(await self.vault.check_token())

    async def test_login(self):
        await self.vault.login()
        self.assertTrue(await self.vault.check_token())

    async def test_login_aim(self):
        if tests.AIM_CONFIG is None or tests.AIM_CONFIG == '' or not os.path.exists(tests.AIM_CONFIG):
            self.skipTest("AIM_CONFIG is not set in init file")
        await self.vault.logoff()
        self.assertFalse(await self.vault.check_token())
        self.vault = aiobastion.EPV(tests.AIM_CONFIG)
        await self.vault.login()
        self.assertTrue(await self.vault.check_token())
        await self.vault.close_session()

    async def test_check_token(self):
        self.assertTrue(await self.vault.check_token())

    async def test_inline_conf(self):
        self.skipTest("Need harcoded credentials")
        config = {'api_host': 'pvwa.acme.fr'}

        production_vault = aiobastion.EPV(serialized=config)
        await production_vault.login("admin", "Cyberark1")
        async with production_vault as epv:
            print(await epv.safe.list())

    async def test_login_pvwa_only(self):
        PVWA_CONFIG = '../../confs/config_test_pvwa_only.yml'
        self.vault = aiobastion.EPV(PVWA_CONFIG)
        with self.assertRaises(aiobastion.exceptions.GetTokenException):
            await self.vault.login(username="admin", password="wrong_password")
        # For a relevant test we need a correct login password that we cant display in code
        # It could be stored in a test safe. For now, we use a wrong password ane assert token exception.
        # self.assertTrue(await self.vault.check_token())



    def test_to_json(self):
        serialized = self.vault.to_json()
        self.assertIsInstance(serialized,dict)
        # self.fail()



if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    unittest.main()
