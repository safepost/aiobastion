import logging
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
        self.test_target_safe = "sample-coolteam"

    async def asyncTearDown(self):
        await self.vault.logoff()

    async def get_random_account_group(self, n=1):
        groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        if n == 1:
            return random.choice(groups)
        else:
            return random.choices(groups, k=n)

    async def get_random_account(self, n=1, platform_id=""):
        search = {"safe": self.test_safe}
        if platform_id != "":
            search["platform"] = platform_id
        accounts = await self.vault.account.search_account_by(
            **search
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
            # Check __str__
            self.assertIn("group_platform", str(members))

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
        # Adding a member of this group to be sure we have one member
        account = await self.get_random_account()
        try:
            await self.vault.accountgroup.add_member(account, group)
        except CyberarkAPIException as err:
            if err.err_code == 400:
                # The account already have a group, we update the group accordingly
                group = await self.vault.account.get_account_group(account)

        members = await self.vault.accountgroup.members(group)

        # Undo
        await self.vault.accountgroup.delete_member(account, group)

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

    async def test_move_all_account_groups(self):
        ag_name = "MoveAccountGroupTest"
        # Create a new account group in test safe
        try:
            group_id = await self.vault.accountgroup.add(ag_name, "sample_group", self.test_safe)
        except CyberarkAPIException as err:
            if err.http_status == 409:
                group_id = await self.vault.accountgroup.get_account_group_id(ag_name, self.test_safe)
            else:
                raise
        # Adding two members of a given platform
        random_accounts = await self.get_random_account(2, "UnixSSH")
        for _r in random_accounts:
            print(f"Adding {_r.name} to {ag_name} (Group ID : {group_id})")
            try:
                await self.vault.accountgroup.add_member(_r, group_id)
            except CyberarkAPIException as err:
                if err.http_status == 400:
                    # Account already added in a group
                    pass
                else:
                    raise

        # Moving accounts group but filtering in our platform to test_target_safe
        # So the account should not be moved !
        filtered = {"platformID": "UnixSSH"}
        try:
            await self.vault.accountgroup.move_all_account_groups(self.test_safe, self.test_target_safe,
                                                                  account_filter=filtered)
        except Exception as err:
            # We have raised StopIteration here
            print(f"Handle me {err}")

        # The account should remain in src safe
        list_of_account_groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        self.assertIn(ag_name, [_l.name for _l in list_of_account_groups])

        # Not in dst safe
        list_of_account_groups = await self.vault.accountgroup.list_by_safe(self.test_target_safe)
        self.assertNotIn(ag_name, [_l.name for _l in list_of_account_groups])


        # Moving account not filtering
        # => expected result : the account is moved

        # Going back to
        #
        # _account_groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        # for _ag in _account_groups:
        #     print(str(_ag))
        #     _ag_members = await self.vault.accountgroup.members(_ag)
        #     print([str(_a) for _a in _ag_members])

            # print(str(a))
        # await self.vault.accountgroup.move_all_account_groups(self.test_safe, )
