import os
import random
import shutil
from pathlib import Path
from unittest import IsolatedAsyncioTestCase
import aiobastion
from aiobastion.exceptions import AiobastionException
import tests

class TestApplication(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

    async def asyncTearDown(self):
        await self.vault.close_session()


    async def get_random_platform(self, n=1):
        platforms = await self.vault.platform.get_target_platforms()
        if n == 1:
            return random.choice(platforms)
        else:
            return random.choices(platforms, k=n)

    async def test_get_target_platform(self):
        platforms = await self.vault.platform.get_target_platforms()
        self.assertGreater(len(platforms), 0)

        platforms = await self.vault.platform.get_target_platforms(active=True)
        self.assertGreater(len(platforms), 0)
        for pf in platforms:
            self.assertTrue(pf["Active"])

        platforms = await self.vault.platform.get_target_platforms(systemType="*NIX")
        self.assertGreater(len(platforms), 0)
        for pf in platforms:
            self.assertEqual(pf["SystemType"], "*NIX")

        platforms = await self.vault.platform.get_target_platforms(periodicVerify=True)
        for pf in platforms:
            self.assertTrue(pf["PeriodicVerify"])

        platforms = await self.vault.platform.get_target_platforms(manualVerify=True)
        for pf in platforms:
            self.assertTrue(pf["CredentialsManagementPolicy"]["Verification"]["AllowManual"])

        platforms = await self.vault.platform.get_target_platforms(periodicChange=True)
        for pf in platforms:
            self.assertTrue(pf["CredentialsManagementPolicy"]["Change"]["PerformAutomatic"])

        platforms = await self.vault.platform.get_target_platforms(manualChange=True)
        for pf in platforms:
            self.assertTrue(pf["CredentialsManagementPolicy"]["Change"]["AllowManual"])

        platforms = await self.vault.platform.get_target_platforms(automaticReconcile=True)
        for pf in platforms:
            self.assertTrue(pf["CredentialsManagementPolicy"]["Reconcile"]["AutomaticReconcileWhenUnsynced"])

        platforms = await self.vault.platform.get_target_platforms(manualReconcile=True)
        for pf in platforms:
            self.assertTrue(pf["CredentialsManagementPolicy"]["Reconcile"]["AllowManual"])

    async def test_get_platforms_details(self):
        pf = await self.get_random_platform()
        details = await self.vault.platform.get_platforms_details(pf["PlatformID"])
        self.assertIn("Details", details)

    async def test_search_target_platform(self):
        # we select a random platform then search on its name and ensure we find something
        pf = await self.get_random_platform()
        search_pf = await self.vault.platform.search_target_platform(pf["Name"])
        self.assertGreaterEqual(len(search_pf), 1)

    async def test_get_target_platform_details(self):
        pf = await self.get_random_platform()
        details = await self.vault.platform.get_target_platform_details(pf["Name"])
        print(details)
        self.assertIn("SystemType", details)

    async def test_get_target_platform_unique_id(self):
        pf = await self.get_random_platform()
        unique_id = await self.vault.platform.get_target_platform_unique_id(pf["PlatformID"])
        self.assertIsInstance(unique_id, int)

    async def test_del_target_plaform(self):
        self.skipTest("We can't delete random platform atm")

    async def test_export_platform(self):
        pf = await self.get_random_platform()
        pf_id = pf["PlatformID"]
        # Create ./temp folder if not exists
        Path("./temp").mkdir(parents=True, exist_ok=True)

        await self.vault.platform.export_platform(pf_id, "temp/")
        self.assertIn(f"{pf_id}.zip", os.listdir("./temp"))

        # Cleanup
        shutil.rmtree("./temp")

    async def test_get_target_platform_connection_components(self):
        pf = await self.get_random_platform()
        unique_id = await self.vault.platform.get_target_platform_unique_id(pf["PlatformID"])

        connection_components = await self.vault.platform.get_target_platform_connection_components(unique_id)
        self.assertGreaterEqual(len(connection_components), 0)

    async def test_get_session_management_policy(self):
        pf = await self.get_random_platform()
        unique_id = await self.vault.platform.get_target_platform_unique_id(pf["PlatformID"])

        mgmt_policy = await self.vault.platform.get_session_management_policy(unique_id)
        # we suppose all our platform have Session Management Policy which could be wrong
        self.assertIn("PSMServerId", mgmt_policy)

    async def test_export_all_platforms(self):
        multiple_pf = await self.get_random_platform(5)
        pf_id = [pf["PlatformID"] for pf in multiple_pf]

        # this platform is non exportable :
        if "PSMSecureConnect" in pf_id: pf_id.remove("PSMSecureConnect")

        # Create ./temp folder if not exists
        Path("./temp").mkdir(parents=True, exist_ok=True)

        print(await self.vault.platform.export_all_platforms("temp/"))
        for pf in pf_id:
            self.assertIn(f"{pf}.zip", os.listdir("./temp"))

        # Cleanup
        shutil.rmtree("./temp")
