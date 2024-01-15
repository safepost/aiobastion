import asyncio
import unittest
from unittest import IsolatedAsyncioTestCase
import aiobastion
import tests


class TestEPV(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        try:
            await self.vault.logoff()
        except:
            # test_logoff 
            pass

    async def test_logoff(self):
        await self.vault.logoff()
        self.assertFalse(await self.vault.check_token())

    async def test_login(self):
        await self.vault.login()
        self.assertTrue(await self.vault.check_token())

    async def test_login_aim(self):
        if tests.AIM_CONFIG is None or tests.AIM_CONFIG == '':
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
        await self.vault.login(username="admin", password="Cyberark1")
        print(await self.vault.safe.list())
        self.assertTrue(await self.vault.check_token())



    def test_to_json(self):
        serialized = self.vault.to_json()
        self.assertIsInstance(serialized,dict)
        # self.fail()



if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    unittest.main()
