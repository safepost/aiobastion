import random
import secrets
import unittest
from unittest import TestCase, IsolatedAsyncioTestCase
import aiobastion
import tests
from aiobastion.exceptions import CyberarkAPIException, CyberarkException, AiobastionException
from aiobastion.accounts import PrivilegedAccount

privileged = PrivilegedAccount("test_account", "platform", "testSafe", address="176.171.20.224", id="78_222")
create_me = PrivilegedAccount("test_account", "UnixSSH", "sample-it-dept", address="176.171.220.224", userName="admin")
create_me2 = PrivilegedAccount("test_account2", "UnixSSH", "sample-it-dept", address="176.171.220.225",
                               userName="admin")
create_me3 = PrivilegedAccount("test_account3", "UnixSSH", "sample-it-dept", address="176.171.220.226",
                               userName="admin")


class TestAccount(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

        self.test_safe = "sample-it-dept"

    async def asyncTearDown(self):
        await self.vault.close_session()
        # await self.vault.logoff()

    async def get_random_account(self, n=1):
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

        rdp_file = await self.vault.account.connect_using_PSM(account.id, cc)
        self.assertIsInstance(rdp_file, bytes)

    async def test_disable_secret_management(self):
        account = await self.get_random_account()
        ret = await self.vault.account.disable_password_management(account)
        self.assertFalse(ret["secretManagement"]["automaticManagementEnabled"])

        # undo
        ret = await self.vault.account.resume_password_management(account)
        self.assertTrue(ret["secretManagement"]["automaticManagementEnabled"])

    async def test_resume_secret_management(self):
        account = await self.get_random_account()
        ret = await self.vault.account.resume_password_management(account)
        self.assertTrue(ret["secretManagement"]["automaticManagementEnabled"])

    async def test_get_password(self):
        account = await self.get_random_account()
        ret = await self.vault.account.get_password(account)
        self.assertIsInstance(ret, str)

        account = await self.get_random_account(15)
        ret = await self.vault.account.get_password(account)
        self.assertIsInstance(ret, list)

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

        get_password = await self.vault.account.get_password(account)
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


if __name__ == '__main__':
    unittest.main()
