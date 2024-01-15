import random
import secrets
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase

import aiobastion
# import aiobastion.EPV
import tests
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException, CyberarkAIMnotFound
from aiobastion.accounts import PrivilegedAccount
from aiobastion.accountgroup import  PrivilegedAccountGroup
from aiobastion import EPV
from typing import List, Union

privileged = PrivilegedAccount("test_account", "platform", "testSafe", address="176.171.20.224", id="78_222")
create_me = PrivilegedAccount("test_account", "UnixSSH", "sample-it-dept", address="176.171.220.224", userName="admin")
create_me2 = PrivilegedAccount("test_account2", "UnixSSH", "sample-it-dept", address="176.171.220.225",
                               userName="admin")
create_me3 = PrivilegedAccount("test_account3", "UnixSSH", "sample-it-dept", address="176.171.220.226",
                               userName="admin")
admin = PrivilegedAccount("admin", "UnixSSH", "sample-it-dept", address="222.192.113.246", userName="admin")
recon = PrivilegedAccount("recon", "UnixSSH", "sample-it-dept", address="222.192.113.246", userName="recon")

class TestAccount(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = EPV(tests.CONFIG)
        await self.vault.login()

        self.test_safe = "sample-it-dept"

    async def asyncTearDown(self):
        await self.vault.logoff()

    async def get_random_account(self, n=1) -> Union[PrivilegedAccount,List[PrivilegedAccount]]:
        accounts = await self.vault.account.search_account_by(
            safe=self.test_safe
        )
        self.assertGreaterEqual(len(accounts), 1)
        if n == 1:
            return random.choice(accounts)
        else:
            return random.choices(accounts, k=n)

    async def get_random_unix_account(self, n=1):
        accounts = await self.vault.account.search_account_by(
            safe=self.test_safe,
            platform="UnixSSH"
        )
        self.assertGreaterEqual(len(accounts), 1)
        if n == 1:
            return random.choice(accounts)
        else:
            return random.choices(accounts, k=n)

    async def test_add_account_to_safe(self):
        already_exists = await self.vault.account.search_account_by(
            username=create_me.userName,
            address=create_me.address,
            safe=create_me.safeName
        )

        if len(already_exists) == 0:
            self.acc_id = await self.vault.account.add_account_to_safe(create_me)
            self.assertRegex(self.acc_id, r'[0-9_]+')

            await self.vault.account.delete(self.acc_id)
        else:
            try:
                await self.vault.account.add_account_to_safe(create_me)
            except:
                self.assertRaises(CyberarkException)

        create_me_list = [create_me, create_me2, create_me3]
        create_me_safe_account_list = await self.vault.account.search_account_by(safe=create_me.safeName)
        create_me_filter = [c for c in create_me_safe_account_list if c.name in [l.name for l in create_me_list]]
        if len(create_me_filter) == 0:
            # No "create_me" accounts were found, we try to create it !
            self.acc_id = await self.vault.account.add_account_to_safe(create_me_list)
            self.assertIsInstance(self.acc_id, list)
            for a in self.acc_id:
                if isinstance(a, CyberarkAPIException):
                    # print(str(a))
                    raise a
                else:
                    self.assertRegex(a, r'[0-9_]+')

            # We're done, now delete accounts
            await self.vault.account.delete(self.acc_id)
        else:
            # print(str(create_me_filter))
            await self.vault.account.delete(create_me_filter)
            self.fail("Conditions to perform the test were not met, but now hopefully we're good")

    async def test_get_account(self):
        account = await self.get_random_account()
        self.assertIsInstance(account, PrivilegedAccount)

        a2 = await self.vault.account.get_account([account.id, account.id])
        for a in a2:
            self.assertEqual(str(account), str(a))
        a2 = await self.vault.account.get_account(account.id)

        self.assertEqual(str(account), str(a2))

        try:
            account = await self.vault.account.get_account("12_1212")
        except:
            self.assertRaises(CyberarkException)


    async def test_get_account_id(self):
        account = await self.get_random_account()
        acc_id = await self.vault.account.get_account_id(account)
        self.assertEqual(acc_id, account.id)

        acc_id = await self.vault.account.get_account_id(account.id)
        self.assertEqual(acc_id, account.id)

    async def test_link_account(self):
        accounts = await self.get_random_account(2)
        ret = await self.vault.account.link_account(accounts[0], accounts[1], 2)
        self.assertTrue(ret)

        undo = await self.vault.account.unlink_account(accounts[0], 2)
        self.assertTrue(undo)

    async def test_link_account_by_address(self):

        for acc in (admin, recon):
            try:
                await self.vault.account.add_account_to_safe(acc)
            except CyberarkAPIException as err:
                if err.http_status == 409:
                    pass
                else:
                    raise

        ret = await self.vault.account.link_reconcile_account_by_address("admin", "recon", "222.192.113.246")
        self.assertTrue(ret)

    async def test_change_password(self):
        # Only unix accounts are mapped to a dummy platform
        account = await self.get_random_unix_account()
        changed = await self.vault.account.change_password(account)
        self.assertTrue(changed)

    async def test_reconcile(self):
        # Only unix accounts are mapped to a dummy platform
        accounts = await self.get_random_unix_account(2)
        # link reconcile address to an address
        ret = await self.vault.account.link_reconciliation_account(accounts[0], accounts[1])
        self.assertTrue(ret)

        # reconcile the address
        ret = await self.vault.account.reconcile(accounts[0])
        self.assertTrue(ret)

        # remove the reconcile address from the address
        undo = await self.vault.account.remove_reconcile_account(accounts[0])
        self.assertTrue(undo)

    async def test_search_account_by_ip_addr(self):
        account = await self.get_random_account()
        s = await self.vault.account.search_account_by_ip_addr(account.address)
        self.assertGreaterEqual(len(s), 1)

    async def test_search_account_by(self):
        account = await self.get_random_account()
        acc = account.to_json()

        s = await self.vault.account.search_account_by(username=account.userName)
        k = [ac.to_json() for ac in s]
        self.assertIn(acc, k)

        s = await self.vault.account.search_account_by(address=account.address)
        k = [ac.to_json() for ac in s]
        self.assertIn(acc, k)

        s = await self.vault.account.search_account_by(safe=account.safeName)
        k = [ac.to_json() for ac in s]
        self.assertIn(acc, k)

        s = await self.vault.account.search_account_by(platform=account.platformId)
        k = [ac.to_json() for ac in s]
        self.assertIn(acc, k)

        s = await self.vault.account.search_account_by(f"{account.platformId} {account.userName}")
        k = [ac.to_json() for ac in s]
        self.assertIn(acc, k)

    async def test_connect_using_PSM(self):
        # Only unix accounts have the connect option
        account = await self.get_random_unix_account()

        # User must be vault admin to retrieve platform, or specify manually the plaform
        cc = "PSM-SSH"

        try:
            unique_id = await self.vault.platform.get_target_platform_unique_id(account.platformId)
            ccs = await self.vault.platform.get_target_platform_connection_components(unique_id)
            # find first active connexion component
            cc = None
            for _cc in ccs:
                if _cc["Enabled"]:
                    cc = _cc["PSMConnectorID"]
                    break
        except CyberarkException as err:
            # You are not Vault Admin
            self.assertIn("PASWS041E", str(err))

        try:
            rdp_file = await self.vault.account.connect_using_PSM(account.id, cc)
        except CyberarkAPIException as err:
            if "Missing mandatory parameter - Reason" in str(err):
                print("Get PSM Connect failed due to reason not provided, try again with reason")
                rdp_file = await self.vault.account.connect_using_PSM(account.id, cc, "random reason")
            else:
                raise
        self.assertIsInstance(rdp_file, bytes)

    async def test_disable_secret_management(self):
        account = await self.get_random_account()
        ret = await self.vault.account.disable_password_management(account)
        self.assertFalse(ret.secretManagement["automaticManagementEnabled"])

        # undo
        ret = await self.vault.account.resume_password_management(account)
        self.assertTrue(ret.secretManagement["automaticManagementEnabled"])

    async def test_resume_secret_management(self):
        account = await self.get_random_account()
        ret = await self.vault.account.resume_password_management(account)
        self.assertTrue(ret.secretManagement["automaticManagementEnabled"])

    async def test_get_password(self):
        async def _get_password(reason):
            account = await self.get_random_account()
            ret = await self.vault.account.get_password(account, reason)
            self.assertIsInstance(ret, str)
 
            account = await self.get_random_account(15)
            ret = await self.vault.account.get_password(account, reason)
            self.assertIsInstance(ret, list)

        try:
            await _get_password(None)
        except CyberarkAPIException as err:
            if "Missing mandatory parameter - Reason" in str(err):
                await _get_password("random reason")
            else:
                raise

        # account = await self.get_random_account()
        # await self.vault.account.set_password(account, 'tutu"tata134!*$$^ABC')
        # ret = await self.vault.account.get_password(account)
        #

    async def test_set_password(self):
        account = await self.get_random_account()
        # Generating new password and ensuring it respect security policy
        new_password = secrets.token_hex(44) + "ac12AB$$"
        ret = await self.vault.account.set_password(account, new_password)
        self.assertTrue(ret)

        get_password = await self.vault.account.get_password(account, "random reason")
        self.assertEqual(new_password, get_password)

    async def test_delete(self):
        account = await self.get_random_account()
        ret = await self.vault.account.delete(account)
        self.assertTrue(ret)
        not_found = await self.vault.account.search_account_by(username=account.userName, address=account.address)
        self.assertEqual(len(not_found), 0)

        ret = await self.vault.account.add_account_to_safe(account)
        self.assertEqual(ret, account.id)

    async def test_get_cpm_status(self):
        # Only unix accounts are mapped to a dummy platform
        account = await self.get_random_unix_account()
        status = await self.vault.account.get_cpm_status(account)
        self.assertIn('automaticManagementEnabled', status)

    async def test_add_member_to_group(self):
        account = await self.get_random_account()
        # Deleting group membership in case of the account is already in a group
        await self.vault.account.del_account_group_membership(account)

        account_group = PrivilegedAccountGroup("sample_group_name", "sample_group", self.test_safe)

        try:
            await self.vault.accountgroup.add_privileged_account_group(account_group)
        except CyberarkAPIException as err:
            if err.http_status == 409:
                print("Group (sample_group_name) was already added before")
            else:
                raise

        ret = await self.vault.account.add_member_to_group(account, "sample_group_name")
        self.assertTrue("AccountId" in ret)

        # undo
        ret = await self.vault.account.del_account_group_membership(account)
        self.assertTrue(ret)

    async def test_get_accountgroup(self):
        account = await self.get_random_account()
        try:
            ret = await self.vault.account.add_member_to_group(account, "sample_group_name")
            self.assertTrue("AccountId" in ret)
        except CyberarkAPIException as err:
            # if the address already belongs to the group
            self.assertEqual(err.err_code, "CAWS00001E")

        acc_group = await self.vault.account.get_account_group(account)
        self.assertRegex(acc_group, r'[0-9_]+')
        ret = await self.vault.account.del_account_group_membership(account)
        self.assertTrue(ret)
        acc_group = await self.vault.account.get_account_group(account)
        self.assertIsNone(acc_group)

    async def test_del_accountgroup(self):
        account = await self.get_random_account()
        # add an address to a group to test the deletion
        try:
            ret = await self.vault.account.add_member_to_group(account, "sample_group_name")
            self.assertTrue("AccountId" in ret)
        except:
            # the address is already username of the group
            pass

        ret = await self.vault.account.del_account_group_membership(account)
        self.assertTrue(ret)
        acc_group = await self.vault.account.get_account_group(account)
        self.assertIsNone(acc_group)

    async def test_cpm_status(self):
        status = ("success", "failure", "Deactivated", "No status (yet)")
        account = await self.get_random_account()
        # print(account.cpm_status())
        self.assertIn(account.cpm_status(), status)

    async def test_last_modified(self):
        account = await self.get_random_account()
        self.assertIsInstance(account.last_modified(True), int)
        self.assertIsInstance(account.last_modified(False), int)

    async def test_is_valid(self):
        self.assertFalse(self.vault.account.is_valid_username("tutut\r\n"))
        self.assertTrue(self.vault.account.is_valid_username("tututu"))
        self.assertFalse(self.vault.account.is_valid_safename("tutut\r\n"))
        self.assertTrue(self.vault.account.is_valid_safename("tututu"))


    async def test_update_using_list(self):
        # testing with 1 account
        account = await self.get_random_account()
        old_username = account.userName
        new_username = "tutu"
        data = [
            {"path": "/userName", "op": "replace", "value": new_username},
        ]
        updated = await self.vault.account.update_using_list(account, data)
        self.assertEqual(updated.userName, new_username)
        data = [
            {"path": "/userName", "op": "replace", "value": old_username},
        ]
        updated = await self.vault.account.update_using_list(account, data)
        self.assertEqual(updated.userName, old_username)

        # testing with N accounts
        accounts = await self.get_random_account(2)
        data = [
            {"path": "/userName", "op": "replace", "value": new_username},
        ]
        updated = await self.vault.account.update_using_list(accounts, data)
        [self.assertEqual(u.userName, new_username) for u in updated]
        for a in accounts:
            data = [{"path": "/userName", "op": "replace", "value": a.userName}]
            updated = await self.vault.account.update_using_list(a, data)
            self.assertEqual(updated.userName, a.userName)

        # Remove FC test
        data = [{"path": "/userName", "op": "remove"},]
        with self.assertRaises(CyberarkAPIException):
            updated = await self.vault.account.update_using_list(account, data)

    async def test_update_single_fc(self):
        account = await self.get_random_account()
        new_username = "tutu"
        updated = await self.vault.account.update_single_fc(account, "userName", new_username)
        self.assertEqual(updated.userName, new_username)

        updated = await self.vault.account.update_single_fc(account, "userName", account.userName)
        self.assertEqual(updated.userName, account.userName)

    async def test_update_file_category(self):
        account = await self.get_random_account()
        new_username = "tutu"
        new_address = "221.112.152.100"
        updated = await self.vault.account.update_file_category(account,
                                                                ["userName", "address"],
                                                                [new_username, new_address])
        self.assertEqual(updated.userName, new_username)
        self.assertEqual(updated.address, new_address)
        updated = await self.vault.account.update_file_category(account,
                                                                ["userName", "address"],
                                                                [account.userName, account.address])
        self.assertEqual(updated.userName, account.userName)
        self.assertEqual(updated.address, account.address)

    async def test_restore_last_cpm_version(self):
        # Unfortunately we have no CPM working on sample accounts
        account = await self.get_random_account()
        with self.assertRaises(AiobastionException):
            await self.vault.account.restore_last_cpm_version(account, "CPM")

    async def test_restore_last_cpm_version_by_cpm(self):
        # Unfortunately we have no CPM working on sample accounts
        account = await self.get_random_account()
        with self.assertRaises(AiobastionException):
            await self.vault.account.restore_last_cpm_version_by_cpm(account, "CPM")

    async def test_get_password_version(self):
        async def _get_password_version(reason):
            account = await self.get_random_account()
            # Generate versions
            versions = []
            for v in range(1, 5):
                generated = secrets.token_hex(44) + "ac12AB$$"
                await self.vault.account.set_password(account, generated)
                versions.append(generated)
         
            all_versions = await self.vault.account.get_secret_versions(account, reason)
            version_id = reversed(sorted([v["versionID"] for v in all_versions]))
         
            for v, z in zip(version_id, reversed(versions)):
                self.assertEqual(z, await self.vault.account.get_secret_version(account, v, reason))
        try:
            await _get_password_version(None)
        except CyberarkAPIException as err:
            if "Missing mandatory parameter - Reason" in str(err):
                await _get_password_version("random reason")
            else:
                raise


    async def test_get_password_aim(self):
        if tests.AIM_CONFIG is None or tests.AIM_CONFIG == '':
            self.skipTest("AIM_CONFIG is not set in init file")
        account = await self.get_random_account()

        # Generating new password and ensuring it respect security policy
        new_password = secrets.token_hex(44) + "ac12AB$$"
        ret = await self.vault.account.set_password(account, new_password)
        self.assertTrue(ret)

        get_password = await self.vault.account.get_password_aim(address=account.address, safe=account.safeName)
        self.assertEqual(new_password, get_password.secret)

        get_secret = await self.vault.account.get_secret_aim(account)
        self.assertEqual(new_password, get_secret.secret)

        with self.assertRaises(CyberarkAIMnotFound):
            await self.vault.account.get_password_aim(address="not_exist")

    async def test_get_secret_aim(self):
        if tests.AIM_CONFIG is None or tests.AIM_CONFIG == '':
            self.skipTest("AIM_CONFIG is not set in init file")
        account = await self.get_random_account(50)

        retrieved_password = await self.vault.account.get_secret(account[15])

        import time
        start_time = time.time()
        get_secret = await self.vault.account.get_secret_aim(account)
        execution_time = time.time() - start_time

        self.assertEqual(retrieved_password, get_secret[15].secret)
        #
        # # print(account[10])


if __name__ == '__main__':
    unittest.main()
