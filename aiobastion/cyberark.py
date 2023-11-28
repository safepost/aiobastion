# -*- coding: utf-8 -*-
import os.path
import asyncio
import json
import ssl
from typing import Tuple, Union
from collections import namedtuple
import copy

from http import HTTPStatus
from aiohttp import ContentTypeError
import aiohttp

from .accountgroup import AccountGroup
from .accounts import Account
from .applications import Applications
from .config import Config
from .exceptions import CyberarkException, GetTokenException, AiobastionException, CyberarkAPIException, \
    ChallengeResponseException, CyberarkAIMnotFound
from .platforms import Platform
from .safe import Safe
from .system_health import SystemHealth
from .users import User, Group
from .utilities import Utilities

class EPV:
    """
    Class that represent the connection, or future connection, to the Vault.
    """

    def __init__(self, configfile: str = None, serialized: dict = None, token: str = None):
        # PVWA initialization
        self.api_host = None                # CyberArk host
        self.authtype = "cyberark"          # CyberArk authentification type

        # Number of parrallel task for PVWA and AIM
        self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
        # Communication timeout in seconds
        self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT
        self.verify = False                 # root certificate authority (CA)

        self.request_params = None          # timeout & ssl setup
        self.__token = token                # CyberArk authorization token

        # AIM Communication initialization
        self.AIM = None                     # EPV_AIM definition

        # Other section initialization
        self.configfile = configfile        # Name of the configuration file
        self.config = None                  # Definition from the configuration file
        self.cpm = ""                       # CPM to assign to safes
        self.retention = Config.CYBERARK_DEFAULT_RETENTION  # days of retention for objects in safe

        if configfile is None and serialized is None:
            raise AiobastionException("You must provide either configfile or serialized to init EPV")
        elif configfile is not None and serialized is None:
            self._epv_config(configfile)
        elif serialized is not None and configfile is None:
            self._epv_serialize(serialized)
        else:
            raise AiobastionException("You must provide either configfile or serialized to init EPV, not both")

        self.user_list = None

        # Session management
        self.session = None
        self.__sema = None

        # utilities
        self.account = Account(self)
        self.platform = Platform(self)
        self.safe = Safe(self)
        self.user = User(self)
        self.group = Group(self)
        self.application = Applications(self)
        self.accountgroup = AccountGroup(self)
        self.system_health = SystemHealth(self)
        self.utils = Utilities(self)

    def _epv_config(self, configfile):
        self.config = Config(configfile)

        # PVWA definition
        self.api_host = self.config.PVWA
        self.authtype = self.config.authtype
        self.max_concurrent_tasks = self.config.max_concurrent_tasks
        self.timeout = self.config.timeout
        self.verify = self.config.PVWA_CA

        # AIM Communication
        if self.config.AIM is not None:
            self.AIM = EPV_AIM(epv=self, **self.config.AIM)

        # Other definition
        self.cpm = self.config.CPM
        self.retention = self.config.retention

    def _epv_serialize(self, serialized):
        if not isinstance(serialized, dict):
            raise AiobastionException("Type error: Parameter 'serialized' must be a dictionary.")

        # Validate dictionary key
        for k in serialized.keys():
            if k not in [
                "AIM",
                "api_host",
                "authtype",
                "cpm",
                "max_concurrent_tasks",
                "retention",
                "timeout",
                "token",
                "verify"]:
                raise AiobastionException(f"Unknown serialized field: {k} = {serialized[k]!r}")

        # PVWA definition
        if "api_host" in serialized:
            self.api_host = serialized['api_host']
        if "authtype" in serialized:
            self.authtype = serialized["authtype"]
        if "max_concurrent_tasks" in serialized:
            self.max_concurrent_tasks = serialized['max_concurrent_tasks']
        if "timeout" in serialized:
            self.timeout = serialized["timeout"]
        if "verify" in serialized:
            self.verify = serialized["verify"]
        if "token" in serialized:
            self.__token = serialized['token']

        # AIM Communication
        if "AIM" in serialized:
            serialized_aim = copy.copy(serialized["AIM"])

            serialized_aim.setdefault("host", getattr(self, "api_host", None))
            serialized_aim.setdefault(
                "max_concurrent_tasks",
                getattr(self, "max_concurrent_tasks", Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS))
            serialized_aim.setdefault("timeout", getattr(self, "timeout", Config.CYBERARK_DEFAULT_TIMEOUT))
            serialized_aim.setdefault("verify", getattr(self, "verify", False))

            self.AIM = EPV_AIM(epv=self, serialized=serialized_aim)

        # Other definition
        if "cpm" in serialized:
            self.cpm = serialized['cpm']
        if "retention" in serialized:
            self.retention = serialized['retention']

    def validate_and_setup_ssl(self):
        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionException(
                    f"Parameter 'verify' (or 'CA') in PVWA: file not found {self.verify!r}")

            if os.path.isdir(self.verify):
                self.request_params = {"timeout": self.timeout,
                      "ssl": ssl.create_default_context(capath=self.verify)}
            else:
                self.request_params = {"timeout": self.timeout,
                      "ssl": ssl.create_default_context(cafile=self.verify)}
        elif self.verify: # True
            self.request_params = {"timeout": self.timeout,
                "ssl": ssl.create_default_context()}
        else: # None or False
            self.request_params = {"timeout": self.timeout, "ssl": False}


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
                    try:
                        error = await req.text()
                    except Exception as err:                                # pylint: disable=broad-exception-caught
                        error = f"Unable to get error message {err}"
                        raise CyberarkException(error) from err

                    if req.status == 403:
                        raise CyberarkException("Invalid credentials ! ")
                    elif req.status == 409:
                        raise CyberarkException("Password expired !")
                    elif req.status == 500 and "ITATS542I" in error:
                        raise ChallengeResponseException
                    else:
                        raise CyberarkException(error)

                tok = await req.text()
                # Closing session because now we are connected and we need to update headers which can be done
                # only by recreating a new session (or passing the headers on each request)
                await session.close()
                return tok.replace('"', '')

        except ChallengeResponseException:
            raise
        except (ConnectionError, TimeoutError) as err:
            raise CyberarkException("Network problem connecting to PVWA") from err
        except Exception as err:
            raise CyberarkException(err) from err

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

        try:
            await self.handle_request("get", "api/LoginsInfo")
            return True
        except CyberarkException:
            return False
        # url, head = self.get_url("api/LoginsInfo")
        # session = self.get_session()
        # # async with aiohttp.ClientSession() as session:
        # async with session.get(url, headers=head, **self.request_params) as req:
        #     if req.status != 200:
        #         self.__token = None
        #         return False
        #     return True

    async def login_with_aim(self, aim_host: str = None, appid: str = None, username: str = None, cert_file: str = None,
                             cert_key: str = None, root_ca=None, timeout: int = None, max_concurrent_tasks: int = None,
                             user_search: dict = None, auth_type=None):
        """ Authenticate the PVWA user using AIM interface to get the secret (password) in CyberArk.

        We only support client certificate authentication to the AIM

        | ℹ️ The following parameters are optional. If a parameter is not set, it will be obtained
            from *EPV* initialization (configuration file or serialization).

        | ⚠️ Any specified parameter from the *login_with_aim* function will override the *EPV_AIM*
            definition.

        :param aim_host: *AIM* CyberArk host
        :param appid: *AIM* Application ID
        :param cert_file: *AIM* Filename public certificat
        :param cert_key: *AIM* Filename private key certificat
        :param root_ca: *AIM* Directory or filename of the ROOT certificate authority (CA)
        :param timeout: *AIM* Maximum wait time in seconds before generating a timeout (default 30 seconds)
        :param max_concurrent_tasks: *AIM* Maximum number of parallel task (default 10)
        :param username: *PVWA* Name of the user who is logging in to the Vault (PVWA username)
        :param auth_type: *PVWA* logon authenticafication method: CyberArk, Windows, LDAP or Radius
        :param user_search: *PVWA* Search parameters to uniquely identify the PVWA user (optional).
        :type user_search: *PVWA* Dictionary

        |     **user_search** dictionary may define any of the following keys:
        |         safe, object, folder, address, database, policyid, failrequestonpasswordchange.
        |         We recommend, if necessary, **safe** and **object** keys to uniquely identify
                  the PVWA user.  Refer to  `CyberArk Central Credential Provider - REST web service`_.

        :raise GetTokenException: Logon error
        :raise AiobastionException: AIM configuration setup error
        """
        # Is AIM attribute defined ?
        if self.AIM:
            # IF AIM is active, it is not too late to change the default configuration
            if self.AIM.session is None:
                # Override AIM attributes with the function parameters
                if aim_host:
                    self.AIM.host = aim_host
                if appid:
                    self.AIM.appid = appid
                if cert_file:
                    self.AIM.cert = cert_file
                if cert_key:
                    self.AIM.key = cert_key
                if root_ca is not None:
                    self.AIM.verify = root_ca
                if timeout:
                    self.AIM.timeout = timeout
                if max_concurrent_tasks:
                    self.AIM.max_concurrent_tasks = max_concurrent_tasks

                # Valide AIM setup
                self.AIM.validate_and_setup_ssl()

            # Complete undefined parameters with AIM and PWVA attributes
            aim_host = (aim_host or self.AIM.host)
            appid = (appid or self.AIM.appid)
            cert_file = (cert_file or self.AIM.cert)
            cert_key = (cert_key or self.AIM.key)
            timeout = (timeout or self.AIM.timeout or self.timeout)
            max_concurrent_tasks = (max_concurrent_tasks or self.AIM.max_concurrent_tasks or self.max_concurrent_tasks)

            if root_ca is None:   # May be false
                if self.AIM.verify is not None:
                    root_ca   = self.AIM.verify
                else:
                    if self.verify is not None:
                        root_ca   = self.verify     # PVWA
                    else:
                        root_ca   = True

            if (aim_host            and aim_host  != self.AIM.host)  or \
               (appid               and appid     != self.AIM.appid) or \
               (cert_file           and cert_file != self.AIM.cert)  or \
               (cert_key            and cert_key  != self.AIM.key)   or \
               (root_ca is not None and root_ca   != self.AIM.verify):
                raise CyberarkException("AIM is already initialized ! Please close EPV before reopen it.")
        else:
            if root_ca is None:
                if self.verify is not None:
                    root_ca = self.verify  # PVWA
                else:
                    root_ca = True

            self.AIM = EPV_AIM(epv=self, host=aim_host, appid=appid, cert=cert_file, key=cert_key, verify=root_ca,
                               timeout=timeout, max_concurrent_tasks=max_concurrent_tasks)

            # Valide AIM setup
            self.AIM.validate_and_setup_ssl()


        # Check mandatory attributs
        if self.AIM.host  is None or \
           self.AIM.appid is None or \
           self.AIM.cert  is None or \
           self.AIM.key   is None:
            raise AiobastionException("Missing AIM mandatory parameters: host, appid, cert, key (and a optional verify).")


        # Complete undefined parameters with PVWA attributes
        if username is None and self.config and self.config.username:
            username = self.config.username

        if username is None:
            raise AiobastionException(
                "Username must be provided on login_with_aim call or in configuration file.")

        if user_search is None and self.config and self.config.user_search:
            user_search = self.config.user_search

        try:
            await self.login(username=username, password=None, auth_type=auth_type, user_search=user_search)

        except (CyberarkAIMnotFound, CyberarkAPIException, CyberarkException, AiobastionException) as err:
            raise GetTokenException(str(err)) from err

    async def login(self, username=None, password=None, auth_type="", user_search=None):
        """ Authenticate the PVWA user to manage of the vault.

        | If the password is not supply, the AIM interface must be define in the EPV initialization
            (configuration file or serialization).  You may also use the login_with_aim function
            instead of the login function which give more flexibility.

        :param username: Name of the PVWA user
        :param password: Password of the PVWA user
        :param auth_type: logon authenticafication method: CyberArk, Windows, LDAP or Radius
        :param user_search: Search parameters to uniquely identify the PVWA user (optional).
        :type user_search: Dictionary

        |     **user_search** dictionary may define any of the following keys:
        |         safe, object, folder, address, database, policyid, failrequestonpasswordchange.
        |         We recommend, if necessary, **safe** and **object** keys to uniquely identify
                  the PVWA user.  Refer to  `CyberArk Central Credential Provider - REST web service`_.

        :raise GetTokenException: Logon error
        :raise AiobastionException: AIM configuration setup error
        :raise ChallengeResponseException: User should enter passcode now
        """

        if await self.check_token():
            return

        if self.api_host is None:
            raise AiobastionException(
                "Host must be provided in configuration file or in EPV(serialized={'api_host: 'CyberArk-host'}).")

        if username is None:
            if self.config is None or self.config.username is None:
                raise AiobastionException(
                    "Username must be provided on login call or in configuration file."
                    " You may also configure the AIM section.")
            username = self.config.username

        if not auth_type:
            if self.authtype:
                auth_type = self.authtype
            else:
                auth_type = "cyberark"

        self.validate_and_setup_ssl()

        if self.AIM and self.AIM.handle_request is None:
            self.AIM.validate_and_setup_ssl()

        if password is None:
            if self.config and self.config.password:
                password = self.config.password
                self.config.password = None
            else:
                if not self.AIM:
                    raise AiobastionException(
                        "Password must be provided on login call or in configuration file."
                        " You may configure the AIM section or call the login_with_aim function.")

                # Valide AIM setup
                self.AIM.validate_and_setup_ssl()

                params = {"UserName": username}

                if user_search is None:
                    if self.config and self.config.user_search:
                        user_search = self.config.user_search

                if user_search:
                    err = EPV_AIM.valid_secret_params(user_search)

                    if err:
                        raise GetTokenException(f"invalid parameter in 'user_search' {err}")

                    params.update(user_search)

                try:
                    # Get password form AIM
                    password = await self.AIM.get_secret(**params)
                except (CyberarkAIMnotFound, CyberarkAPIException, CyberarkException) as err:
                    raise GetTokenException(str(err)) from err


        try:
            self.__token = await self.__login_cyberark(username, password, auth_type)
            # update the session
            await self.close_session()
        # except ChallengeResponseException:
        #     # User should enter passcode now
        #     raise
        except CyberarkException as err:
            raise GetTokenException(str(err)) from err

    def get_session(self):
        if self.__token is None and self.session is None:
            head = {"Content-type": "application/json", "Authorization": "None"}
            self.session = aiohttp.ClientSession(headers=head)
        elif self.__token is None and self.session is not None:
            # This should never happen
            return self.session
        elif self.session is None:
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head)
        elif self.session.closed:
            # This should never happen, but it's a security in case of unhandled exceptions
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head)

        if self.__sema is None:
            self.__sema = asyncio.Semaphore(self.max_concurrent_tasks)

            if self.AIM:
                self.AIM.set_semaphore(self.__sema, self.session)

        return self.session

    async def close_session(self):
        try:
            if self.AIM:
                await self.AIM.close_session()

            if self.session:
                await self.session.close()
        except (CyberarkException, AttributeError):
            pass
        self.session = None
        self.__sema = None

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
            "api_host": self.api_host,
            "authtype": self.authtype,
            "timeout": self.timeout,
            "verify": self.verify,
            "cpm": self.cpm,
            "retention": self.retention,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "token": self.__token
        }

        # AIM Communication
        if self.AIM:
            serialized["AIM"] = self.AIM.to_json()

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
        assert method.lower() in ("post", "delete", "get", "patch", "put")

        url, head = self.get_url(short_url)

        session = self.get_session()

        async with self.__sema:
            async with session.request(method, url, json=data, headers=head, params=params,
                                       **self.request_params) as req:
                if req.status in (200, 201, 204):
                    try:
                        if len(await req.read()) == 0:
                            return True
                        else:
                            return filter_func(await req.json())
                    except ContentTypeError:
                        response = await req.text()
                        try:
                            return json.loads(response)
                        except (ContentTypeError, json.decoder.JSONDecodeError):
                            if len(response) > 0:
                                return response
                            else:
                                return True
                        #except:
                        #    raise
                else:
                    if req.status == 404:
                        raise CyberarkException(f"404 error with URL {url}")
                    elif req.status == 401:
                        raise CyberarkException("You are not logged, you need to login first")
                    elif req.status == 405:
                        raise CyberarkException("Your PVWA version does not support this function")
                    try:
                        content = await req.json(content_type=None)
                    except (KeyError, ValueError, ContentTypeError) as err:
                        raise CyberarkException(f"Error with CyberArk status code {str(req.status)}") from err

                    if "Details" in content:
                        details = content["Details"]
                    else:
                        details = ""

                    if "ErrorCode" in content and "ErrorMessage" in content:
                        raise CyberarkAPIException(req.status, content["ErrorCode"],
                                                   content["ErrorMessage"], details)
                    else:
                        raise CyberarkAPIException(req.status, "NO_ERR_CODE", content)
            # except Exception as err:
            #     raise CyberarkException(err)


# AIM section
AIM_secret_resp = namedtuple('AIM_secret_resp', ['secret', 'detail'])


class EPV_AIM:
    """
    Class managing communication with the Central Credential Provider (AIM) GetPassword Web Service
    """
    _serialized_fields = ["host", "appid", "cert", "key", "verify", "timeout", "max_concurrent_tasks"]
    _getPassword_request_parm = ["safe", "folder", "object", "username", "address", "database",
                                 "policyid", "reason", "connectiontimeout", "query", "queryformat",
                                 "failrequestonpasswordchange"]

    def __init__(self, host: str = None, appid: str = None, cert: str = None, key: str = None,
                 verify: Union[str, bool] = None,
                 timeout: int = Config.CYBERARK_DEFAULT_TIMEOUT,
                 max_concurrent_tasks: int = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS,
                 serialized:dict = None, epv: EPV = None):

        self.host = host
        self.appid = appid
        self.cert = cert
        self.key = key
        self.verify  = verify
        self.timeout = timeout
        self.max_concurrent_tasks = max_concurrent_tasks

        # Session management
        self.epv = epv
        self.__sema = None
        self.session = None
        self.request_params = None

        if serialized:
            for k,v in serialized.items():
                keyname = k.lower()
                if keyname in EPV_AIM._serialized_fields:
                    setattr(self, keyname, v)
                else:
                    raise AiobastionException(f"Unknown serialized AIM field: {k} = {v!r}")


        # Optional attributs
        if self.timeout is None:
            self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT

        if self.max_concurrent_tasks is None:
            self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS

    def validate_and_setup_ssl(self):
        if self.session:
            return

        # Check mandatory attributs
        for attr_name in ["host", "appid", "cert", "key"]:
            v = getattr(self, attr_name, None)

            if v is None:
                raise AiobastionException(f"Missing AIM mandatory parameter '{attr_name}'."
                                          " Required parameters: host, appid, cert, key.")

        if not os.path.exists(self.cert):
            raise AiobastionException(f"Parameter 'cert' in AIM: Public certificate file not found: {self.cert!r}")

        if not os.path.exists(self.key):
            raise AiobastionException(f"Parameter 'key' in AIM: Private key certificat file not found: {self.key!r}")

        if self.verify is None or \
           (isinstance(self.verify, str) and not os.path.exists(self.verify)):
            raise AiobastionException(f"Parameter 'verify' in AIM: file not found {self.verify!r}")

        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionException(f"Parameter 'verify' in AIM: file not found {self.verify!r}")

            if os.path.isdir(self.verify):
                ssl_context = ssl.create_default_context(capath=self.verify)
                ssl_context.load_cert_chain(self.cert, self.key)
            else:
                ssl_context = ssl.create_default_context(cafile=self.verify)
                ssl_context.load_cert_chain(self.cert, self.key)
        else:  # None, True or False
            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(self.cert, self.key)

        self.request_params = \
            {"timeout": self.timeout,
            "ssl": ssl_context}


    @staticmethod
    def valid_secret_params(params: dict = None) -> str:
        error_str = ""

        if not isinstance(params, dict):
            error_str = "parameter is not a dictionary"
        else:
            # Must be a list of keys to modify the dictionary key (not the dictionary itself)
            for k in list(params.keys()):
                key_lower = k.lower()

                if key_lower not in EPV_AIM._getPassword_request_parm:
                    error_str = f"unknown parameter: {k}={params[k]}"
                    break

                if k != key_lower:
                    params[key_lower] = params.pop(k)

        return error_str

    def set_semaphore(self, sema, session):
        """ Initialize the semaphore of the AIM interface,
            so that EPV and EPV_AIM could share the same semaphore.
        """
        if not self.__sema:
            self.__sema = sema

        if not self.session:
            if self.request_params is None:
                self.validate_and_setup_ssl()

            self.session = session

    def to_json(self):
        serialized = {}

        for attr_name in EPV_AIM._serialized_fields:
            serialized[attr_name] = getattr(self, attr_name, None)

        return serialized

    def get_url(self, url) -> Tuple[str, dict]:
        addr = f"https://{self.host}/AIMWebService/api/{url}"
        head = {"Content-type": "application/json"}

        return addr, head

    # Context manager
    async def __aenter__(self):
        self.get_session()

        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close_session()

    def get_session(self):
        if self.session is None:
            if self.request_params is None:
                self.validate_and_setup_ssl()

            if self.epv.session:
                self.session = self.epv.session
            else:
                self.session = aiohttp.ClientSession()

        if self.__sema is None:
            # This statement is wrong:
            #    if self.epv.__sema:
            #        self.__sema = self.epv.__sema
            if self.epv._EPV__sema:                         # pylint: disable=protected-access
                self.__sema = self.epv._EPV__sema           # pylint: disable=protected-access
            else:
                self.__sema = asyncio.Semaphore(self.max_concurrent_tasks)

        return self.session

    async def close_session(self):
        try:
            if self.session:
                # Are we using the epv.session, if so don't close it
                if self.epv.session is None or (self.epv.session and self.epv.session != self.session):
                    await self.session.close()
        except (CyberarkException, AttributeError) as err:
            pass

        self.session = None
        self.__sema = None

    async def get_secret(self, **kwargs):
        """
        This function allow to search using one or more parameters and return list of address id
        :param kwargs: any searchable key = value
        |   like:  UserName, Safe, Folder, Object (which is name),
        |          Address, Database, PolicyID, Reason, Query, QueryFormat,
                   FailRequestOnPasswordChange, ...
        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Execution error
        :return: The password
        """

        secret_detail = await self.get_secret_detail(**kwargs)

        return secret_detail.secret

    async def get_secret_detail(self, **kwargs):
        """
        Retrieve the secret from the GetPassword Web Service Central Credential Provider (AIM)
        ℹ️ The following parameters are optionnal searchable keys. Refer to  `CyberArk Central Credential Provider - REST web service`_.

        :param username: User account name
        :param safe: Safe where the account is stored.
        :param object: Name of the account to retrieve (unique for a specific safe).
        :param folder: Name of the folder property
        :param address: Address account property
        :param database: Database account property
        :param policyid: Policy account property
        :param reason: The reason for retrieving the password. This reason will be audited in
            the Credential Provider audit log.
        :param query: Defines a free query using account properties, including Safe, folder, and object.
            When this method is specified, all other search criteria
            (Safe/Folder/ Object/UserName/Address/PolicyID/Database) are ignored and only the
            account properties that are specified in the query are passed to the Central
            Credential Provider in the password request.
        :param queryformat: Defines the query format, which can optionally use regular expressions.
            Possible values are: *Exact* or *Regexp*.
        :param failrequestonpasswordchange: Boolean, Whether or not an error will be returned if
            this web service is called when a password change process is underway.
        :return:  namedtuple of (secret, detail)
        |    secret = password
        |    detail = dictionary from the Central Credential Provider (AIM) GetPassword Web Service
        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :raise AiobastionException: AIM configuration setup error
        :return:  namedtuple of (secret, detail)
            secret = password
            detail = dictionary from the Central Credential Provider (AIM) GetPassword Web Service
        """

        detail_info = await self.handle_request("get", "Accounts", params=kwargs)
        secret_detail = AIM_secret_resp(detail_info["Content"], detail_info)

        return secret_detail

    @staticmethod
    def handle_error_detail_info(url: str = None, params: dict = None):
        # Mask the appid attribute, if you are a security maniac
        if "appid" in params:
            params_new = copy.copy(params)
            params_new["appid"] = "<hidden>"
        else:
            params_new = params

        return f"url: {url}, params: {params_new}"

    async def handle_request(self, method: str, short_url: str, params: dict = None, filter_func=lambda x: x):
        """
        Function that handles AIM requests to the API
        :param method: "get"
        :param params: dictonary parameters for CyberArk like Safe, Object, UserName, Address,
            Reason, Query, ...
        :param short_url: piece of URL after AIMWebService/api/
        :param filter_func:
        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :return: dictonary return by CyberArk
        """
        assert method.lower() == "get"

        url, head = self.get_url(short_url)
        session = self.get_session()

        if 'applid' not in params:
            params_new = copy.copy(params)
            params_new.setdefault('appid', self.appid)
        else:
            params_new = params

        async with self.__sema:
            try:
                async with session.request(method, url, headers=head, params=params_new, **self.request_params) as req:
                    # if req.status == 404:
                    #     raise CyberarkException(f"Error 404 : Endpoint {url} not found")

                    try:
                        resp_json = await req.json()
                        if req.status == 200:
                            if "Content" not in resp_json:
                                raise CyberarkAPIException(req.status, "INVALID_JSON",
                                                           "Could not find the password ('Content')",
                                                           EPV_AIM.handle_error_detail_info(url, params_new))

                            return filter_func(resp_json)
                        else:
                            # This is a error
                            if "Details" in resp_json:
                                details = resp_json["Details"]
                            else:
                                details = EPV_AIM.handle_error_detail_info(url, params_new)

                            if "ErrorCode" in resp_json and "ErrorMsg" in resp_json:
                                if resp_json["ErrorCode"] == "APPAP004E":
                                    raise CyberarkAIMnotFound(req.status, resp_json["ErrorCode"], resp_json["ErrorMsg"],
                                                              details)
                                else:
                                    raise CyberarkAPIException(req.status, resp_json["ErrorCode"],
                                                               resp_json["ErrorMsg"], details)
                            else:
                                http_error = HTTPStatus(req.status)

                                raise CyberarkAPIException(req.status, "HTTP_ERR_CODE", http_error.phrase, details)

                    except json.decoder.JSONDecodeError as err:
                        http_error = HTTPStatus(req.status)
                        details = EPV_AIM.handle_error_detail_info(url, params_new)
                        raise CyberarkAPIException(req.status, "HTTP_ERR_CODE", http_error.phrase, details) from err

                    except (KeyError, ValueError, ContentTypeError) as err:
                        # http_error = HTTPStatus(req.status)
                        details = EPV_AIM.handle_error_detail_info(url, params_new)
                        raise CyberarkException(
                            f"HTTP error {req.status}: {str(err)} || Additional Details : {details}") from err

            except aiohttp.ClientError as err:
                details = EPV_AIM.handle_error_detail_info(url, params_new)
                raise CyberarkException(f"HTTP error: {str(err)} || Additional Details : {details}") from err
