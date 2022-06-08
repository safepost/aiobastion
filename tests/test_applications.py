from unittest import IsolatedAsyncioTestCase
import aiobastion
from aiobastion.exceptions import AiobastionException
import tests

class TestApplication(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.vault = aiobastion.EPV(tests.CONFIG)
        await self.vault.login()

        self.app_name = "TestApp"
        self.app_name2 = "TestApp2"

    async def asyncTearDown(self):
        await self.vault.close_session()

    async def test_del_all_authentication(self):
        # Cleanup all authentications
        auths = await self.vault.application.get_authentication(self.app_name)
        for auth in auths:
            await self.vault.application.del_authentication(self.app_name, auth["authID"])

        # control
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(len(auths),0)

    async def test_details(self):
        app = await self.vault.application.details(self.app_name)
        self.assertEqual(app["AppID"], self.app_name)

        # Failed
        # For this test we have 2 apps: TestApp and TestApp2
        try:
            app = await self.vault.application.details("TestAp")
        except Exception as err:
            self.assertIsInstance(err, AiobastionException)

    async def test_search(self):
        apps = await self.vault.application.search("App")
        self.assertIn(self.app_name, apps)
        self.assertIn(self.app_name2, apps)

    async def test_get_authentication(self):
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(len(auths), 0)

    async def test_add_path_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name, path="mypath")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['AuthValue'], "mypath")

        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)

    async def test_add_hash_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name, hash_string="randomhash",
                                                                  comment="comment")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['AuthValue'], "randomhash")
        self.assertEqual(auths[0]['Comment'], "comment")


        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)


    async def test_add_os_user_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name, os_user="myuser")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['AuthValue'], "myuser")

        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)

    async def test_add_address_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name, address="10.12.13.14")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['AuthValue'], "10.12.13.14")

        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)

    async def test_add_serial_number_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name, serial_number="123456789",
                                                                  comment="avec un certificat")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['AuthValue'], "123456789")
        self.assertEqual(auths[0]['Comment'], "avec un certificat")

        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)

    async def test_add_certificate_authentication(self):
        # add authentication
        updated = await self.vault.application.add_authentication(self.app_name,
                                                                  issuer="CN=PKI Entreprise",
                                                                  subject="CN=Appli,OU=Application,DC=fr")
        self.assertTrue(updated)

        # check
        auths = await self.vault.application.get_authentication(self.app_name)
        self.assertEqual(auths[0]['Issuer'], "CN=PKI Entreprise")
        self.assertEqual(auths[0]['Subject'], "CN=Appli,OU=Application,DC=fr")

        # delete
        updated = await self.vault.application.del_authentication(self.app_name, auths[0]['authID'])
        self.assertTrue(updated)
