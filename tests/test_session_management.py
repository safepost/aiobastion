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
