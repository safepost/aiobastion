import asyncio
import random
import secrets
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase
import aiobastion
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException
from aiobastion.accounts import PrivilegedAccount
import tests
import time


class TestSessionManagement(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.AIM_CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        await self.vault.close_session()

    async def test_get_all_connection_components(self):
        all_cc = await self.vault.session_management.get_all_connection_components()
        self.assertGreater(all_cc["Total"], 5)
