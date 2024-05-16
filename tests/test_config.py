<<<<<<< HEAD
import os
import sys
import asyncio
import unittest
from unittest import IsolatedAsyncioTestCase
import aiobastion
import tests
from aiobastion import CyberarkException


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


if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
=======
import os
import sys
import asyncio
import unittest
from unittest import IsolatedAsyncioTestCase
import aiobastion
import tests
from aiobastion import CyberarkException


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


if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
>>>>>>> d06df4a570e5fc5f0b18a46849d1a5b0932898da
