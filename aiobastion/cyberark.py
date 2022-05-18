# -*- coding: utf-8 -*-
import json
import ssl
from typing import Tuple

import aiohttp
from aiohttp import ContentTypeError

from .abstract import Vault
from .accountgroup import AccountGroup
from .accounts import Account
from .applications import Applications
from .config import Config
from .exceptions import CyberarkException, GetTokenException, AiobastionException, CyberarkAPIException
from .platforms import Platform
from .safe import Safe
from .users import User, Group
from .utilities import Utilities


class EPV(Vault):
    def __init__(self, configfile: str = None, serialized: dict = None, token: str = None):
        if configfile is None and serialized is None:
            raise AiobastionException("You must provide either configfile or serialized to init EPV")
        if configfile is not None and serialized is not None:
            raise AiobastionException("You must provide either configfile or serialized to init EPV, not both")
        if configfile is not None:
            self.config = Config(configfile)
            self.api_host = self.config.PVWA
            # self.request_params = {"timeout": self.config.timeout, "verify": self.config.CA}
            if self.config.PVWA_CA is not False:
                self.request_params = {"timeout": self.config.timeout,
                                       "ssl": ssl.create_default_context(cafile=self.config.PVWA_CA)}
            else:
                self.request_params = {"timeout": self.config.timeout, "ssl": False}

            self.api_host = self.config.PVWA
            self.cpm = self.config.CPM
            self.retention = self.config.retention
            self.__token = token

        if serialized is not None:
            if serialized["verify"] is not False:
                self.request_params = {"timeout": serialized["timeout"],
                                       "ssl": ssl.create_default_context(cafile=serialized["verify"])}
            else:
                self.request_params = {"timeout": serialized["timeout"], "ssl": False}
            self.api_host = serialized['api_host']
            self.cpm = serialized['cpm']
            self.retention = serialized['retention']
            self.__token = serialized['token']

        # self.session = requests.Session()

        self.user_list = None
        self.session = None

        # utilities
        self.account = Account(self)
        self.platform = Platform(self)
        self.safe = Safe(self)
        self.user = User(self)
        self.group = Group(self)
        self.application = Applications(self)
        self.accountgroup = AccountGroup(self)
        self.utils = Utilities(self)

    # Context manager
    async def __aenter__(self):
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return await self.close_session()

    # start of functions definition
    async def __login_cyberark(self, username: str, password: str, auth_type: str) -> str:
        assert self.__token is None
        assert auth_type.upper() in ("CYBERARK", "WINDOWS", "LDAP", "RADIUS")
        url, head = self.get_url("API/Auth/" + auth_type + "/Logon")
        request_data = {"username": username, "password": password, "concurrentSession": True}
        try:
            session = self.get_session()
            async with session.post(url, json=request_data, **self.request_params) as req:
                if req.status != 200:
                    if req.status == 403:
                        raise CyberarkException("Invalid credentials ! ")
                    elif req.status == 409:
                        raise CyberarkException("Password expired !")
                    else:
                        try:
                            raise CyberarkException(await req.text())
                        except Exception as err:
                            raise CyberarkException(f"Unknown error, HTTP {str(req.status)}, ERR : {str(err)}")

                tok = await req.text()
                return tok.replace('"', '')
            # req = self.session.post(url, headers=head, data=json.dumps(request_data), **self.request_params)
            # Cleaning password after authentication
            self.__password = ""
        except (ConnectionError, TimeoutError):
            raise CyberarkException("Network problem connecting to PVWA")
        except Exception as err:
            raise CyberarkException(err)

    async def logoff(self):
        url, head = self.get_url("API/Auth/Logoff")
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=head, **self.request_params) as req:
                if req.status != 200:
                    raise CyberarkException("Error disconnecting to PVWA with code : %s" % str(req.status))
        await self.close_session()
        self.__token = None
        return True

    async def check_token(self) -> bool or None:
        if self.__token is None:
            return None
        url, head = self.get_url("api/LoginsInfo")
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=head, **self.request_params) as req:
                # req = self.session.get(url, headers=head, **self.request_params)
                if req.status != 200:
                    self.__token = None
                    return False
                return True

    async def get_aim_secret(self, aim_host, appid, username, cert_file: str, cert_key: str, ca_file):
        if appid is None:
            raise AiobastionException("Missing mandatory parameter : AppID")

        if cert_file is None and cert_key is None:
            raise AiobastionException("Provide cert_file and cert_key arguments in order to connect")

        try:

            url = f"https://{aim_host}/AIMWebService/api/Accounts"
            data = {
                "AppId": appid,
                "Username": username
            }

            if ca_file is not False:
                sslcontext = ssl.create_default_context(cafile=ca_file)
                sslcontext.load_cert_chain(cert_file, cert_key)
            else:
                sslcontext = ssl.create_default_context()
                sslcontext.load_cert_chain(cert_file, cert_key)

            req_params = {"timeout": self.config.timeout, "ssl": sslcontext}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=data, **req_params) as req:
                    result = await req.json()

            return result["Content"]

        except Exception:
            raise

    async def login_with_aim(self, aim_host, appid, username, cert_file: str, cert_key: str, root_ca=False):
        if self.check_token():
            return
        password = await self.get_aim_secret(aim_host, appid, username, cert_file, cert_key, root_ca)

        try:
            self.__token = self.__login_cyberark(username, password, self.config.authtype)
        except CyberarkException as err:
            raise GetTokenException(err)

    async def login(self, username=None, password=None, auth_type="Cyberark"):
        if await self.check_token():
            return

        if username is None:
            if self.config.username is None:
                raise AiobastionException("Username must be provided on login call or in configuration file")
            username = self.config.username
        if password is None:
            if self.config.password is None:
                if self.config.AIM is not None:
                    if self.config.AIM:
                        # All infos regarding AIM auth were given in the configuration file
                        password = await self.get_aim_secret(self.config.AIM_HOST, self.config.AIM_AppID, username,
                                                             self.config.AIM_Cert, self.config.AIM_Key,
                                                             self.config.AIM_CA)
                    else:
                        raise AiobastionException(
                            "Missing AIM information to perform AIM authentication, see documentation")
                else:
                    raise AiobastionException("Password must be provided on login call or in configuration file")
            else:
                password = self.config.password

        if self.config.authtype is not None:
            auth_type = self.config.authtype

        try:
            self.__token = await self.__login_cyberark(username, password, auth_type)
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}

            # update the session
            await self.session.close()
            self.session = aiohttp.ClientSession(headers=head)

        except CyberarkException as err:
            raise GetTokenException(err)

    def get_session(self):
        if self.__token is None:
            head = {"Content-type": "application/json", "Authorization": "None"}
            self.session = aiohttp.ClientSession(headers=head)
        elif self.session is None:
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head)

        return self.session

    async def close_session(self):
        await self.session.close()
        self.session = None

    def get_url(self, url) -> Tuple[str, dict]:
        addr = 'https://' + self.api_host + '/PasswordVault/' + url
        if self.__token is None:
            head = {"Content-type": "application/json", "Authorization": "None"}
        else:
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}

        return addr, head

    def to_json(self):
        serialized = {
            "api_host": self.config.PVWA,
            "timeout": self.config.timeout,
            "verify": self.config.PVWA_CA,
            "cpm": self.config.CPM,
            "retention": self.config.retention,
            "token": self.__token,
        }
        return serialized

    async def get_version(self):
        server_infos = await self.handle_request("GET", "WebServices/PIMServices.svc/Server",
                                                 filter_func=lambda x: x["ExternalVersion"])
        return server_infos

    def versiontuple(self, v):
        return tuple(map(int, (v.split("."))))

    async def handle_request(self, method: str, short_url: str, data=None, params: dict = None,
                             filter_func=lambda x: x):
        """
        Function that handles requests to the API
        :param filter_func:
        :param params:
        :param method:
        :param short_url: piece of URL after PasswordVault/
        :param data: valid json data if needed
        :return:
        """
        assert method.lower() in ("post", "delete", "get", "patch")

        url, head = self.get_url(short_url)

        # try:

        session = self.get_session()
        async with session.request(method, url, json=data, params=params, **self.request_params) as req:
            if req.status in (200, 201, 204):
                try:
                    if len(await req.read()) == 0:
                        return True
                    else:
                        return filter_func(await req.json())
                    # return filter_func(await req.json())
                except ContentTypeError:
                    response = await req.text()
                    try:
                        return json.loads(response)
                    except ContentTypeError:
                        # if response.startswith('"') and response.endswith('"'):
                        #     # remove double quotes from string
                        #     return response[1:-1]
                        if len(response) > 0:
                            return response
                        else:
                            return True
                    except:
                        raise
            else:
                if req.status == 404:
                    raise CyberarkException(f"404 error with URL {url}")
                try:
                    content = await req.json(content_type=None)
                except (KeyError, ValueError, ContentTypeError):
                    raise CyberarkException(f"Error with Cyberark status code {str(req.status)}")

                if "Details" in content:
                    details = content["Details"]
                else:
                    details = ""
                    # TODO gérer l'erreur HTTP 401, CAWS00001E : La connexion au Vault a été interrompue.
                    # => signifie qu'il n'y a pas eu de login()
                if "ErrorCode" in content and "ErrorMessage" in content:
                    raise CyberarkAPIException(req.status, content["ErrorCode"], content["ErrorMessage"], details)
                else:
                    raise CyberarkAPIException(req.status, "NO_ERR_CODE", content)
        # except Exception as err:
        #     raise CyberarkException(err)
