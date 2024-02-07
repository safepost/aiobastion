# -*- coding: utf-8 -*-
import logging
import os.path
import asyncio
import json
import ssl
from typing import Tuple
import copy

from aiohttp import ContentTypeError
import aiohttp

from .accountgroup import AccountGroup
from .accounts import Account
from .aim import EPV_AIM
from .applications import Applications
from .config import Config
from .exceptions import CyberarkException, GetTokenException, AiobastionException, CyberarkAPIException, \
    ChallengeResponseException, CyberarkAIMnotFound
from .platforms import Platform
from .safe import Safe
from .system_health import SystemHealth
from .users import User, Group
from .utilities import Utilities
from .session_management import SessionManagement


class EPV:
    """
    Class that represent the connection, or future connection, to the Vault.
    """

    def __init__(self, configfile: str = None, serialized: dict = None, token: str = None):
        # Logging stuff
        logger: logging.Logger = logging.getLogger("aiobastion")
        self.logger = logger

        # PVWA initialization
        self.api_host = None  # CyberArk host
        self.authtype = "cyberark"  # CyberArk authentification type

        # Number of parrallel task for PVWA and AIM
        self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
        # Communication timeout in seconds
        self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT
        self.verify = Config.CYBERARK_DEFAULT_VERIFY  # root certificate authority (CA)

        self.request_params = {"timeout": self.timeout, "ssl": False}          # timeout & ssl setupn default value
        self.__token = token                # CyberArk authorization token

        # AIM Communication initialization
        self.AIM = None  # EPV_AIM definition

        # Other section initialization
        self.configfile = configfile  # Name of the configuration file
        self.config = None  # Definition from the configuration file
        self.cpm = ""  # CPM to assign to safes
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
        self.session_management = SessionManagement(self)
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
            self.AIM = EPV_AIM(**self.config.AIM)

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
                "verify",
            ]:
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
            serialized_aim.setdefault("verify", getattr(self, "verify", Config.CYBERARK_DEFAULT_VERIFY))

            self.AIM = EPV_AIM(serialized=serialized_aim)

        # Other definition
        if "cpm" in serialized:
            self.cpm = serialized['cpm']
        if "retention" in serialized:
            self.retention = serialized['retention']

    def validate_and_setup_ssl(self):
        if self.verify is None:
            self.verify = Config.CYBERARK_DEFAULT_VERIFY

        if not (isinstance(self.verify, str) or isinstance(self.verify, bool)):
            raise AiobastionException(f"Invalid type for parameter 'verify' (or 'CA') in PVWA: {type(self.verify)} value: {self.verify!r}")

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
        elif self.verify:  # True
            self.request_params = {"timeout": self.timeout,
                                   "ssl": ssl.create_default_context()}
        else:  # False
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
        :raise CyberarkException: Runtime error
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
                self.AIM.validate_and_setup_aim_ssl()

            # Complete undefined parameters with AIM and PWVA attributes
            aim_host = (aim_host or self.AIM.host)
            appid = (appid or self.AIM.appid)
            cert_file = (cert_file or self.AIM.cert)
            cert_key = (cert_key or self.AIM.key)
            timeout = (timeout or self.AIM.timeout or self.timeout)
            max_concurrent_tasks = (max_concurrent_tasks or self.AIM.max_concurrent_tasks or self.max_concurrent_tasks)

            if root_ca is None:  # May be false
                if self.AIM.verify is not None:
                    root_ca = self.AIM.verify
                else:
                    if self.verify is not None:
                        root_ca = self.verify  # PVWA
                    else:
                        root_ca = Config.CYBERARK_DEFAULT_VERIFY

            if (aim_host and aim_host != self.AIM.host) or \
                    (appid and appid != self.AIM.appid) or \
                    (cert_file and cert_file != self.AIM.cert) or \
                    (cert_key and cert_key != self.AIM.key) or \
                    (root_ca is not None and root_ca != self.AIM.verify):
                raise CyberarkException("AIM is already initialized ! Please close EPV before reopen it.")
        else:
            if root_ca is None:
                if self.verify is not None:
                    root_ca = self.verify  # PVWA
                else:
                    root_ca = Config.CYBERARK_DEFAULT_VERIFY

            self.AIM = EPV_AIM(host=aim_host, appid=appid, cert=cert_file, key=cert_key, verify=root_ca,
                               timeout=timeout, max_concurrent_tasks=max_concurrent_tasks)

            # Valid AIM setup
            self.AIM.validate_and_setup_aim_ssl()

        # Check mandatory attributs
        if self.AIM.host is None or \
                self.AIM.appid is None or \
                self.AIM.cert is None or \
                self.AIM.key is None:
            raise AiobastionException(
                "Missing AIM mandatory parameters: host, appid, cert, key (and a optional verify).")

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

        | If the password is not supply, the AIM interface must be defined in the EPV initialization
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

        if self.AIM and self.AIM.handle_aim_request is None:
            self.AIM.validate_and_setup_aim_ssl()

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
                self.AIM.validate_and_setup_aim_ssl()

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
        self.logger.debug(f"Getting aiobastion session ({self.session})")
        if self.__token is None and self.session is None:
            head = {"Content-type": "application/json", "Authorization": "None"}
            self.session = aiohttp.ClientSession(headers=head)
            self.logger.debug(f"Building session ID : {self.session}")
        elif self.__token is None and self.session is not None:
            # This should never happen
            return self.session
        elif self.session is None:
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head)
            self.logger.debug(f"Building session ID (token is known) : {self.session}")

        elif self.session.closed:
            # This should never happen, but it's a security in case of unhandled exceptions
            self.logger.debug("Never happens scenario happened (Session closed but not None)")
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head)

        if self.__sema is None:
            self.__sema = asyncio.Semaphore(self.max_concurrent_tasks)

            if self.AIM:
                self.AIM.set_semaphore(self.__sema, self.session)

        return self.session

    async def close_session(self):
        self.logger.debug("Closing session")
        try:
            if self.AIM:    # This is used, at least, when login is perform
                await self.AIM.close_aim_session()

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
            "token": self.__token,
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
                        # except:
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
