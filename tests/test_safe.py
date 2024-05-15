from unittest import IsolatedAsyncioTestCase
import aiobastion
import random
import tests
from aiobastion import CyberarkAPIException, CyberarkException, AiobastionException


class TestSafe(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()
        self.api_user = "bastion_test_usr"
        self.test_safe = "sample-it-dept"
        self.test_usr = "bastion_std_usr"

    async def asyncTearDown(self):
        await self.vault.logoff()


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
        safes = await self.vault.safe.search()
        self.assertGreaterEqual(len(safes), 1)
        if n == 1:
            return random.choice(safes)
        else:
            return random.choices(safes, k=n)

    async def test_add_member_profile(self):
        with self.assertRaises(CyberarkAPIException):
            ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, "tutu")

        # Trying to remove first in case of the user is already username
        try:
            await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        except CyberarkException:
            pass

        ret = await self.vault.safe.add_member_profile(self.test_safe, self.test_usr, "use")
        self.assertIn("memberId", ret)

        # check already username exception
        with self.assertRaises(CyberarkAPIException):
            ret = await self.vault.safe.add_member_profile(self.test_safe, self.test_usr, "use")

        # undo
        ret = await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        self.assertTrue(ret)

        custom_perm = {"UseAccounts": True}
        ret = await self.vault.safe.add_member_profile(self.test_safe, self.test_usr, custom_perm)
        self.assertIn("memberId", ret)

        # undo
        ret = await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        self.assertTrue(ret)

    async def test_add_member(self):

        with self.assertRaises(CyberarkAPIException):
            ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, "tutu")

        # Trying to remove first in case of the user is already username
        try:
            await self.vault.safe.remove_member(self.test_safe, self.test_usr)
        except CyberarkException:
            pass

        ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, useAccounts=True, listAccounts=True)
        self.assertIn("memberId", ret)

        # check already username exception
        with self.assertRaises(CyberarkAPIException):
            ret = await self.vault.safe.add_member(self.test_safe, self.test_usr, useAccounts=True, listAccounts=True)

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

    async def test_get(self):
        safe = await self.vault.safe.get_safe_details(self.test_safe)
        self.assertEqual(self.test_safe, safe['safeName'])
        [ self.assertIn(k, safe) for k in ['safeName', 'description', 'accounts']]
        self.assertNotIn("no_such_attribute", safe)

    async def test_list_members(self):
        members = await self.vault.safe.list_members(self.test_safe)
        self.assertIn(self.api_user, members)

        with self.assertRaises(AiobastionException):
            members = await self.vault.safe.list_members(self.test_safe, filter_perm="tutu")

        members = await self.vault.safe.list_members(self.test_safe, filter_perm="listAccounts")
        self.assertIn(self.api_user, members)

        members = await self.vault.safe.list_members(self.test_safe, details=True)
        self.assertIn(self.api_user, [m["username"] for m in members])

    async def test_get_members(self):
        members = await self.vault.safe.list_members(self.test_safe)
        self.assertIn(self.api_user, members)

    async def test_is_member_of(self):
        self.assertTrue(await self.vault.safe.is_member_of(self.test_safe, self.api_user))

    async def test_get_permissions(self):
        ret = await self.vault.safe.get_permissions(self.test_safe, self.api_user)
        self.assertIsInstance(ret, dict)
        self.assertIn("listAccounts", ret.keys())

    async def test_list(self):
        ret = await self.vault.safe.list()
        self.assertIn(self.test_safe, ret)

        ret = await self.vault.safe.list(details=True)
        self.assertIn(self.test_safe, [r["safeName"] for r in ret])

    async def test_search_safe(self):
        ret = await self.vault.safe.search()
        safes_names = [r["safeName"] for r in ret]
        self.assertIn(self.test_safe, safes_names)

    async def test_v1_get_safes(self):
        ret = await self.vault.safe.v1_get_safes()
        self.assertIn(self.test_safe, self.test_safe)

    async def test_rename_safe(self):
        # s = await self.get_random_safe(1)
        safe_to_rename = "RENAME_ME"
        new_name = "I_AM_RENAMED"
        try:
            ret = await self.vault.safe.rename(safe_to_rename, new_name)
        except AiobastionException:
            raise
        self.assertIn(new_name, [s["safeName"] for s in await self.vault.safe.search(new_name)])
        # undo
        ret = await self.vault.safe.rename(new_name, safe_to_rename)
        self.assertIn(safe_to_rename, [s["safeName"] for s in await self.vault.safe.search(safe_to_rename)])

if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()

