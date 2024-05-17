import sys
import logging
import random
import time
import unittest
import asyncio
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


    async def test_move_account_group(self):
        self.skipTest("Not for daily usage but run it twice if you work on account group functions")
        ag_name = "MoveAccountGroupTest"

        source_safe = ""
        target_safe = ""

        # Where is "MoveAccountGroupTest"
        ag_test_safe = await self.vault.accountgroup.list_by_safe(self.test_safe)
        ag_target_safe = await self.vault.accountgroup.list_by_safe(self.test_target_safe)

        # Worst case
        if ag_name in [_a.name for _a in ag_target_safe] and \
                ag_name in [_a.name for _a in ag_test_safe]:
            # We have MoveAccountGroupTest in both safes
            _group_test_safe = next(_a for _a in ag_test_safe if _a.name == ag_name)
            _group_target_safe = next(_a for _a in ag_target_safe if _a.name == ag_name)

            _move1 = await self.vault.accountgroup.members(_group_test_safe)
            _move2 = await self.vault.accountgroup.members(_group_target_safe)
            if len(_move1) > len(_move2):
                # More members on ag_test_safe
                source_safe = self.test_safe
                target_safe = self.test_target_safe
                group_id = _group_test_safe.id
            else:
                # More members on ag_target_safe
                source_safe = self.test_target_safe
                target_safe = self.test_safe
                group_id = _group_target_safe.id

        # account_group is already on target
        elif ag_name in [_a.name for _a in ag_target_safe]:
            source_safe = self.test_target_safe
            target_safe = self.test_safe
            _group_target_safe = next(_a for _a in ag_target_safe if _a.name == ag_name)
            group_id = _group_target_safe.id
        # account_group is on source or test was never done before
        elif ag_name in [_a.name for _a in ag_test_safe]:
            source_safe = self.test_safe
            target_safe = self.test_target_safe
            _group_test_safe = next(_a for _a in ag_test_safe if _a.name == ag_name)
            group_id = _group_test_safe.id
        else:
            # Test was never run before
            group_id = await self.vault.accountgroup.add(ag_name, "sample_group", self.test_safe)
            source_safe = self.test_safe
            target_safe = self.test_target_safe

        if len(await self.vault.accountgroup.members(group_id)) == 0:
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
        else:
            print("Not adding more members on this group now")

        try:
            new_gid = await self.vault.accountgroup.move_account_group(ag_name, source_safe, target_safe)
        except Exception as err:
            raise

        # New group should have members now
        self.assertGreater(len(await self.vault.accountgroup.members(new_gid)), 0)


    async def test_move_all_account_groups(self):
        self.skipTest('Avoiding this test because we need to sleep long time for reverting, what we dont like')
        ag_name = "MoveAccountGroupTest"
        # Create a new account group in test safe
        try:
            group_id = await self.vault.accountgroup.add(ag_name, "sample_group", self.test_safe)
        except CyberarkAPIException as err:
            if err.http_status == 409:
                group_id = await self.vault.accountgroup.get_account_group_id(ag_name, self.test_safe)
            else:
                raise

        if len(await self.vault.accountgroup.members(group_id)) == 0:
            # Adding two members of a given platform
            random_accounts = await self.get_random_account(2, "UnixSSH")
            for _r in random_accounts:
                # print(f"Adding {_r.name} to {ag_name} (Group ID : {group_id})")
                try:
                    await self.vault.accountgroup.add_member(_r, group_id)
                except CyberarkAPIException as err:
                    if err.http_status == 400:
                        # Account already added in a group
                        pass
                    else:
                        raise
        else:
            print("Not adding more members on this group now")

        # Moving accounts group but filtering in our platform to test_target_safe
        # So the account should not be moved !
        filtered = {"platformID": "UnixSSH"}
        try:
            await self.vault.accountgroup.move_all_account_groups(self.test_safe, self.test_target_safe,
                                                                  account_filter=filtered)
        except Exception as err:
            raise

        # The account should remain in src safe
        list_of_account_groups = await self.vault.accountgroup.list_by_safe(self.test_safe)
        self.assertIn(ag_name, [_l.name for _l in list_of_account_groups])

        # Not in dst safe
        list_of_account_groups = await self.vault.accountgroup.list_by_safe(self.test_target_safe)
        try:
            self.assertNotIn(ag_name, [_l.name for _l in list_of_account_groups])
        except AssertionError:
            print("Group was found in dst safe probably because another test failed")

        try:
            await self.vault.accountgroup.move_all_account_groups(self.test_safe, self.test_target_safe)
        except Exception as err:
            raise

        # In src safe, the account group should be empty now

        # This one raise a 404 => no member
        with self.assertRaises(CyberarkException):
            print(await self.vault.accountgroup.members(group_id))

        # self.assertEqual(0,len(await self.vault.accountgroup.members(group_id)))

        # In dst safe we should have the new group
        list_of_account_groups = await self.vault.accountgroup.list_by_safe(self.test_target_safe)
        self.assertIn(ag_name, [_l.name for _l in list_of_account_groups])

        # Cyberark has an incorrect behaviour if you move quickly account from a safe to another and vice versa
        # He has an internal cache and thinks the account still exists if it was deleted just before
        # So we need to wait for long for Cyberark to clear its cache
        time.sleep(8)
        # Revert
        try:
            await self.vault.accountgroup.move_all_account_groups(self.test_target_safe, self.test_safe)
        except Exception as err:
            raise

        for _r in await self.vault.accountgroup.members(group_id):
            try:
                await self.vault.accountgroup.delete_member(_r, group_id)
            except:
                pass

if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
