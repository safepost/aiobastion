<<<<<<< HEAD
import asyncio
import os
import random
import secrets
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase
import aiobastion
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException
from aiobastion.accounts import PrivilegedAccount
import tests
import time


@unittest.skipIf(not os.path.exists(tests.AIM_CONFIG), "AIM Config File does Not Exist")
class TestSessionManagement(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.AIM_CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        await self.vault.close_session()

    async def test_get_all_connection_components(self):
        all_cc = await self.vault.session_management.get_all_connection_components()
        self.assertGreater(all_cc["Total"], 5)

if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
=======
import asyncio
import os
import random
import secrets
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase
import aiobastion
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException
from aiobastion.accounts import PrivilegedAccount
import tests
import time


@unittest.skipIf(not os.path.exists(tests.AIM_CONFIG), "AIM Config File does Not Exist")
class TestSessionManagement(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.AIM_CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        await self.vault.close_session()

    async def test_get_all_connection_components(self):
        all_cc = await self.vault.session_management.get_all_connection_components()
        self.assertGreater(all_cc["Total"], 5)

if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
>>>>>>> d06df4a570e5fc5f0b18a46849d1a5b0932898da
