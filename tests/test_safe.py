from unittest import IsolatedAsyncioTestCase
import bastion
import random
import tests
from bastion import CyberarkAPIException, CyberarkException, BastionException


class TestSafe(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = bastion.EPV(tests.CONFIG)
        await self.vault.login()
        self.api_user = "bastion_test_usr"
        self.test_safe = "sample-it-dept"
        self.test_usr = "bastion_std_usr"

    async def get_random_account(self, n=1):
        accounts = await self.vault.account.search_account_by(
            safe=self.test_safe
        )
        self.assertGreaterEqual(len(accounts), 1)
        if n == 1:
            return random.choice(accounts)
        else:
            return random.choices(accounts, k=n)

    async def get_random_safe(self, n=2):
        safes = await self.vault.safe.get_safes()
        self.assertGreaterEqual(len(safes), 1)
        if n == 1:
            return random.choice(safes)
        else:
            return random.choices(safes, k=n)

    async def test_add_member(self):
        with self.assertRaises(AssertionError):
            ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, "tutu")

        # Trying to remove first in case of the user is already username
        try:
            await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        except CyberarkException:
            pass

        ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, "use")
        self.assertIn("memberId", ret)

        # check already username exception
        with self.assertRaises(CyberarkAPIException):
            ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, "use")

        # undo
        ret = await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        self.assertTrue(ret)

        custom_perm = {"UseAccounts": True}
        ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, custom_perm)
        self.assertIn("memberId", ret)

        # undo
        ret = await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        self.assertTrue(ret)

    async def test_remove_member(self):
        self.skipTest("Already covered in test_add_safe_member")

    async def test_exists(self):
        self.assertTrue(await self.vault.safe.exists(self.test_safe))
        self.assertFalse(await self.vault.safe.exists("hiiohhioiohihoih"))

    async def test_add(self):
        try:
            await self.vault.safe.delete("test_safe_creation")
        except CyberarkException:
            pass

        ret = await self.vault.safe.add("test_safe_creation", "test_safe", days=0)
        self.assertIn("safeNumber", ret)
        ret = await self.vault.safe.list()
        self.assertIn("test_safe_creation", ret)

        await self.vault.safe.delete("test_safe_creation")
        ret = await self.vault.safe.list()
        self.assertNotIn("test_safe_creation", ret)

    async def test_add_defaults_admin(self):
        self.skipTest("Test covered by test_create_safe")

    async def test_delete(self):
        self.skipTest("Test covered by test_create_safe")

    async def test_list_members(self):
        members = await self.vault.safe.list_members(self.test_safe)
        self.assertIn(self.api_user, members)

        with self.assertRaises(BastionException):
            members = await self.vault.safe.list_members(self.test_safe, filter_perm="tutu")

        members = await self.vault.safe.list_members(self.test_safe, filter_perm="listAccounts")
        self.assertIn(self.api_user, members)

        members = await self.vault.safe.list_members(self.test_safe, details=True)
        self.assertIn(self.api_user, [m["username"] for m in members])

    async def test_get_members(self):
        members = await self.vault.safe.list_members(self.test_safe)
        self.assertIn(self.api_user, members)

    async def test_is_member_of(self):
        self.assertTrue(self.vault.safe.is_member_of(self.test_safe, self.api_user))

    async def test_get_permissions(self):
        ret = await self.vault.safe.get_permissions(self.test_safe, self.api_user)
        self.assertIsInstance(ret, dict)
        self.assertIn("listAccounts", ret.keys())

    async def test_list(self):
        ret = await self.vault.safe.list()
        self.assertIn(self.test_safe, ret)

