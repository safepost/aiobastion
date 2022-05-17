from .abstract import Vault
from .exceptions import AiobastionException


# class AamObject:
#     def __init__(self, appid: str, params: dict, cert_file: str = None, cert_key: str = None):
#         self.appid = appid
#         self.params = params
#         if cert_file is not None and cert_key is not None:
#             self.cert = (cert_file, cert_key)
#         else:
#             self.cert = None


class Applications:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def details(self, app_name: str):
        url = "WebServices/PIMServices.svc/Applications/"
        params = {
            "AppID": app_name,
        }
        apps = await self.epv.handle_request("get", url, params=params, filter_func=lambda x: x["application"])
        for app in apps:
            if app["AppID"] == app_name:
                return app

        if len(apps) > 1:
            app_names = [x["AppID"] for x in apps]
            raise AiobastionException(f"Provided name {app_name} returns more than one application : {app_names}")
        elif len(apps) == 0:
            raise AiobastionException(f"No results found for {app_name}")

    async def search(self, search: str):
        """
        Search applications by name
        :param search: free text to search application
        :return: list of application names
        """
        url = "WebServices/PIMServices.svc/Applications/"
        params = {
            "AppID": search,
        }
        apps = await self.epv.handle_request("get", url, params=params, filter_func=lambda x: x["application"])
        return [x["AppID"] for x in apps]

    async def add_authentication(self, app_name: str, path: str = None, hash_string: str = None, os_user: str = None,
                                 address: str = None, serial_number: str = None, issuer: list = None,
                                 subject: list = None,
                                 subject_alternative_name: list = None, is_folder: bool = False,
                                 allow_internal_scripts: bool = False, comment: str = "") -> bool:
        """
        Add one or more authentication methods to a given app_id with a named param
        :param app_name: the name of the application
        :param path: path to authenticated
        :param hash_string: hash of script / binary
        :param os_user: os user that is running the script / binary
        :param address: IP address
        :param serial_number: certificate serial number
        :param issuer: list of certificate issuer (PVWA >= 11.4)
        :param subject: list of certificate subject (PVWA >= 11.4)
        :param subject_alternative_name: list of certificate SAN (eg ["DNS Name=www.example.com","IP Address=1.2.3.4"])
        :param allow_internal_scripts: relevant for path authentication only (False by default)
        :param is_folder: relevant for path authentication only (False by default)
        :param comment: relevant for hash and certificate serial number
        :return: boolean telling whether the application was updated or not
        """

        updated = False

        url = f'WebServices/PIMServices.svc/Applications/{app_name}/Authentications/'

        if path is not None:
            body = {
                "authentication": {
                    "AuthType": "path",
                    "AuthValue": path,
                    "IsFolder": is_folder,
                    "AllowInternalScripts": allow_internal_scripts
                }
            }
            updated = await self.epv.handle_request("post", url, data=body)

        if hash_string is not None:
            body = {
                "authentication": {
                    "AuthType": "hash",
                    "AuthValue": hash_string,
                    "Comment": comment
                }
            }
            updated = await self.epv.handle_request("post", url, data=body)

        if os_user is not None:
            body = {
                "authentication": {
                    "AuthType": "osUser",
                    "AuthValue": os_user
                }
            }
            updated = await self.epv.handle_request("post", url, data=body)

        if address is not None:
            body = {
                "authentication": {
                    "AuthType": "machineAddress",
                    "AuthValue": address
                }
            }
            updated = await self.epv.handle_request("post", url, data=body)

        if serial_number is not None:
            body = {
                "authentication": {
                    "AuthType": "certificateserialnumber",
                    "AuthValue": serial_number,
                    "Comment": comment
                }
            }
            updated = await self.epv.handle_request("post", url, data=body)

        if issuer is not None or subject is not None or subject_alternative_name is not None:
            if isinstance(issuer, str):
                issuer = [issuer]
            if isinstance(subject, str):
                subject = [subject]
            if isinstance(subject_alternative_name, str):
                subject_alternative_name = [subject_alternative_name]

            body = {
                "authentication": {
                    "AuthType": "certificateattr",
                }
            }

            if issuer:
                body["authentication"]["Issuer"] = issuer
            if subject:
                body["authentication"]["Subject"] = subject
            if subject_alternative_name:
                body["authentication"]["SubjectAlternativeName"] = subject_alternative_name

            updated = await self.epv.handle_request("post", url, data=body)

        if updated:
            return True
        else:
            return False

    async def get_authentication(self, app_name: str) -> list or bool:
        """
        Get authenticated methods for an application

        :param app_name: The name of the application
        :return: a list of authentication methods
        """
        return await self.epv.handle_request(
            "get",
            f'WebServices/PIMServices.svc/Applications/{app_name}/Authentications',
            filter_func=lambda x: x['authentication'])

    async def del_authentication(self, app_name: str, auth_id: str) -> list or bool:
        """
        Delete authentication method identified by auth_id for the application

        :param app_name: name of the application
        :param auth_id: retrieved with the get_authentication function
        :return: a boolean
        """
        return await self.epv.handle_request(
            "delete",
            f'WebServices/PIMServices.svc/Applications/{app_name}/Authentications/{auth_id}',
            filter_func=lambda x: x['authentication'])
