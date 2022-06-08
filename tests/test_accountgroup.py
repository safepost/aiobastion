import random
from unittest import IsolatedAsyncioTestCase
import aiobastion
import tests
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException
from aiobastion.accountgroup import PrivilegedAccountGroup


class TestAccountGroup(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

        self.test_safe = "sample-it-dept"

    async def asyncTearDown(self):
        await self.vault.close_session()


    async def get_random_account_group(self, n=1):
        groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        if n == 1:
            return random.choice(groups)
        else:
            return random.choices(groups, k=n)

    async def get_random_account(self, n=1):
        accounts = await self.vault.account.search_account_by(
            safe=self.test_safe
        )
        self.assertGreaterEqual(len(accounts), 1)
        if n == 1:
            return random.choice(accounts)
        else:
            return random.choices(accounts, k=n)

    async def test_to_json(self):
        ret = await self.vault.accountgroup.list_by_safe(self.test_safe)
        for members in ret:
            self.assertIsInstance(members.to_json(), dict)

    async def test_list_by_safe(self):
        ret = await self.vault.accountgroup.list_by_safe(self.test_safe)
        for members in ret:
            self.assertIsInstance(members, PrivilegedAccountGroup)

    async def test_get_group_id(self):
        group = await self.get_random_account_group()
        group_id = await self.vault.accountgroup.get_group_id(group)
        self.assertRegex(group_id, r'\d+_\d+')

        with self.assertRaises(AiobastionException):
            await self.vault.accountgroup.get_group_id("toto")

        group_id2 = await self.vault.accountgroup.get_group_id(group_id)
        self.assertEqual(group_id2, group_id)

        group.id = ""
        group_id2 = await self.vault.accountgroup.get_group_id(group)
        self.assertEqual(group_id2, group_id)

        group.name = "toto"
        with self.assertRaises(AiobastionException):
            await self.vault.accountgroup.get_group_id(group)

        group = 22
        with self.assertRaises(AiobastionException):
            await self.vault.accountgroup.get_group_id(group)

    async def test_members(self):
        group = await self.get_random_account_group()
        members = await self.vault.accountgroup.members(group)
        # are we sure the address group have members ? not sure !
        self.assertGreater(len(members), 0)
        self.assertIsInstance(members, list)

    async def test_add(self):
        # Unfortunately we can't delete Account Group so the test is only relevant the first time
        with self.assertRaises(AiobastionException):
            await self.vault.accountgroup.add("toto", "titi", "tata")

        try:
            await self.vault.accountgroup.add("AccountGroupTest", "sample_group", self.test_safe)
        except CyberarkAPIException as err:
            if err.http_status == 409:
                self.skipTest("Group was already added before")
            else:
                raise

        groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        g = [x.name for x in groups]
        self.assertIn("AccountGroupTest", g)

    async def test_add_privileged_account_group(self):
        account_group = PrivilegedAccountGroup("AccountGroupTest", "sample_group", self.test_safe)
        bad_account_group = PrivilegedAccountGroup("bad", "non-existent-group", "non-existent-safe")

        with self.assertRaises(AiobastionException):
            await self.vault.accountgroup.add_privileged_account_group(bad_account_group)

        try:
            await self.vault.accountgroup.add_privileged_account_group(account_group)
        except CyberarkAPIException as err:
            if err.http_status == 409:
                self.skipTest("Group was already added before")
            else:
                raise
        groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        g = [x.name for x in groups]
        self.assertIn(account_group.name, g)

    async def test_add_member(self):
        group = await self.get_random_account_group()
        account = await self.get_random_account()

        # ensure the address do not belong to the group
        try:
            await self.vault.accountgroup.delete_member(account, group)
        except:
            pass

        await self.vault.accountgroup.add_member(account, group)
        members = await self.vault.accountgroup.members(group)
        self.assertIn(account.id, [x.id for x in members])

        # undo
        await self.vault.accountgroup.delete_member(account, group)
        members = await self.vault.accountgroup.members(group)
        self.assertNotIn(account.id, [x.id for x in members])




