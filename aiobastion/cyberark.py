# -*- coding: utf-8 -*-
import logging
import os.path
import asyncio
import json
import ssl
from typing import Tuple, Optional, Union
import copy

from aiohttp import ContentTypeError
import aiohttp

from .accountgroup import AccountGroup
from .accounts import Account
from .aim import EPV_AIM
from .applications import Applications
from .config import Config, validate_integer, validate_bool
from .exceptions import CyberarkException, GetTokenException, AiobastionException, CyberarkAPIException, \
    ChallengeResponseException, CyberarkAIMnotFound, AiobastionConfigurationException
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
    # List of EPV attributes for serialization (to_json)
    _SERIALIZED_FIELDS_OUT = [
        "api_host",
        "authtype",
        # "cpm",                # Now in save
        "keep_cookies",
        "max_concurrent_tasks",
        # "password",           # Hidden
        # "retention",          # Now in save
        "timeout",
        "token",                # use self.__token
        # "user_search",        # Hidden
        # "username",           # Hidden
        "verify",
    ]


    def __init__(self, configfile: str = None, token: str = None, serialized: dict = None):
        # Logging stuff
        logger: logging.Logger = logging.getLogger("aiobastion")
        self.logger = logger

        # PVWA initialization (this initialization is only for pylint)
        self.api_host = None              # CyberArk host
        self.authtype = None              # CyberArk authentification type
        self.keep_cookies = None          # Whether to keep cookies between API calls
        self.max_concurrent_tasks = None  # Maximum number of parallel task
        self.password = None              # Cyberar user password
        self.timeout = None               # Communication timeout in seconds
        self.user_search = None           # Search parameters to uniquely identify the PVWA user
        self.username = None              # CyberArk username
        self.verify = None                # root certificate authority (CA)
        self.__token = token              # CyberArk authorization token

        # TODO: Move to User class in user.py (not EPV class)
        self.user_list = None   # Use in user.py

        # read configuration file or serialization
        self.config = Config(configfile=configfile, serialized=serialized, token=token)

        # Validate and define EPV Class attributes
        self._init_validate_class_attributes(self.config.options_modules["cyberark"], self.config.configfile)


        # Execution parameters
        self.request_params = None        # timeout & ssl setupn default value

        # Session management
        self.session = None
        self.cookies = None
        self.__sema = None

        self.AIM = None                   # AIM interface

        if self.config.options_modules["aim"]:
            AIM_definition = EPV_AIM._init_validate_class_attributes(self.config.options_modules["aim"], "aim", self, configfile=self.config.configfile)
            # Do not define AIM if not necessary.
            if AIM_definition:
                self.AIM = EPV_AIM(**AIM_definition)

        self.account = Account(self, **(
            Account._init_validate_class_attributes(self.config.options_modules["account"], "account", self.config.configfile)))
        self.accountgroup = AccountGroup(self, **(
            AccountGroup._init_validate_class_attributes(self.config.options_modules["accountgroup"], "accountgroup", self.config.configfile)))
        self.application = Applications(self, **(
            Applications._init_validate_class_attributes(self.config.options_modules["applications"], "applications", self.config.configfile)))
        self.group = Group(self, **(
            Group._init_validate_class_attributes(self.config.options_modules["group"], "group", self.config.configfile)))
        self.platform = Platform(self, **(
            Platform._init_validate_class_attributes(self.config.options_modules["platform"], "platform", self.config.configfile)))
        self.safe = Safe(self, **(
            Safe._init_validate_class_attributes(self.config.options_modules["safe"], "safe", self.config.configfile)))
        self.session_management = SessionManagement(self, **(
            SessionManagement._init_validate_class_attributes(self.config.options_modules["sessionmanagement"], "sessionmanagement", self.config.configfile)))
        self.system_health = SystemHealth(self, **(
            SystemHealth._init_validate_class_attributes(self.config.options_modules["systemhealth"], "systemhealth", self.config.configfile)))
        self.user = User(self, **(
            User._init_validate_class_attributes(self.config.options_modules["user"], "user", self.config.configfile)))
        self.utils = Utilities(self, **(
            Utilities._init_validate_class_attributes(self.config.options_modules["utilities"], "utilities", self.config.configfile)))

        # Cleanup usager interface, remove "options_modules" from self.config.
        # This will leave:
        #   configfile
        #   custom
        #   label
        del self.config.options_modules


    def _init_validate_class_attributes(self, serialized: dict, configfile: str) -> dict:
        """_init_validate_class_attributes      Initialize, validate and define the EPV attributes
            from configuration file or serialization

            :param serialized:      Dictionary of the serialized attributes
            :param configfile:      Configuration file name
            :raise AiobastionConfigurationException:  Invalid string or boolean value
            :return:                Dictionary of the EPV attributes class to define


            Synomyms for configuration file:
                api_host, host
                max_concurrent_tasks, masktasks
                verify, ca

            All keys are already in lowercase.
        """
        def section_name(keyname: str) -> str:
            """section_name  Identify the section name of the keyname in the configuration file
            return:
                {str}   "<section>/<keyname>" or "<keyname>"
            """
            section = epv_section.get(keyname, None)

            if section:
                return f"{section}/{keyname}"

            return keyname

        if configfile:
            # Identify the section name of the keyname in the configuration file
            epv_section = {
                "api_host": "pvwa",
                "authtype": "connection",
                "ca": "pvwa",                   # Synonym
                "host": "pvwa",                 # Synonym
                "keep_cookies": "pvwa",
                "masktasks": "pvwa",            # Synonym
                "max_concurrent_tasks": "pvwa",
                "password": "connection",
                "timeout": "pvwa",
                "token": "pvwa",                # changed to __token
                "user_search": "connection",
                "verify": "pvwa",
            }
        else:
            configfile = "serialized"
            epv_section = {}

        self.api_host     = None
        self.authtype     = None
        self.keep_cookies = None
        self.max_concurrent_tasks = None
        self.password     = None
        self.timeout      = None
        self.user_search  = None
        self.username     = None
        self.verify       = None

        # self.__token =  None

        synonym_max_concurrent_tasks = 0
        synonym_verify = 0

        for k, v in serialized.items():
            synonym_max_concurrent_tasks = 0

            if k in ["api_host", "host"]:
                if self.api_host:
                    raise AiobastionConfigurationException(
                        f"Duplicate parameter '{section_name(k)}' in {configfile}. Specify only one.")

                self.api_host = v
            elif k == "authtype":
                self.authtype = v
            elif k == "keep_cookies":
                self.keep_cookies = validate_bool(configfile, section_name(k), v)
            elif k == "maxtasks" or k == "max_concurrent_tasks":
                synonym_max_concurrent_tasks += 1
                self.max_concurrent_tasks = validate_integer(configfile, section_name(k), v)

                if synonym_max_concurrent_tasks > 1:
                    raise AiobastionConfigurationException(
                        f"Duplicate synonym parameter '{section_name(k)}': "
                        f"in {configfile}. Specify only 'max_concurrent_tasks' and remove 'maxtasks'.")


            elif k == "password":
                self.password = v
            elif k == "timeout":
                self.timeout = validate_integer(configfile, section_name(k), v)
            elif k == "token":    # For serialiszation only
                self.__token = serialized['token']
            elif k == "user_search":
                self.user_search = v

                err = EPV_AIM.valid_secret_params(v)

                if err:
                    raise AiobastionConfigurationException(f"invalid parameter in '{section_name(k)}': {err}")

            elif k == "username":
                self.username = v
            elif k in ["verify", "ca"]:
                synonym_verify += 1

                if isinstance(v, str) or isinstance(v, bool):
                    self.verify = v
                else:
                     raise AiobastionConfigurationException(
                            f"Parameter type invalid '{section_name(k)}' "
                            f"in {configfile}: {v!r}")

                if synonym_verify > 1:
                    raise AiobastionConfigurationException(
                        f"Duplicate synonym parameter '{section_name(k)}': "
                        f"in {configfile}. Specify only 'verifiy' and remove 'ca'.")


            else:
                raise AiobastionConfigurationException(
                    f"Unknown attribute '{k}' in {configfile}: {v!r}")

        # Default value if not initialized
        if self.authtype is None:
            self.authtype     = "cyberark"

        if self.keep_cookies is None:
            self.keep_cookies = Config.CYBERARK_DEFAULT_KEEP_COOKIES
        if self.max_concurrent_tasks is None:
            self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
        if self.timeout is None:
            self.timeout      = Config.CYBERARK_DEFAULT_TIMEOUT
        if self.verify is None:
            self.verify       = Config.CYBERARK_DEFAULT_VERIFY

        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionConfigurationException(
                    f"CA certificat File not found {self.verify!r} (Parameter 'verify' in PVWA).")


    def validate_and_setup_ssl(self):
        if self.verify is None:
            self.verify = Config.CYBERARK_DEFAULT_VERIFY

        if not (isinstance(self.verify, str) or isinstance(self.verify, bool)):
            raise AiobastionException(f"Invalid type for parameter 'verify' (or 'CA') in PVWA: {type(self.verify)} value: {self.verify!r}")

        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionException(
                    f"CA certificat File not found {self.verify!r} (Parameter 'verify' in PVWA).")

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
                # Copy the cookies to insert into later sessions
                if self.keep_cookies:
                    self.cookies = session.cookie_jar.filter_cookies(f"https://{self.api_host}")  # type: ignore
                    for cookie in self.cookies:
                        self.cookies[cookie]['domain'] = self.api_host
                # Closing session because now we are connected and we need to update headers which can be done
                # only by recreating a new session (or passing the headers on each request). However, since the session
                # token is only recognized by the PVWA instance that issued the token, load-balancers need to enable session
                # stickiness which is often done with cookies.
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
            self.cookies and session.cookie_jar.update_cookies(self.cookies)
            async with session.post(url, headers=head, **self.request_params) as req:
                if req.status != 200:
                    raise CyberarkException("Error disconnecting to PVWA with code : %s" % str(req.status))
        await self.close_session()
        self.__token = None
        self.cookies = None

        return True

    async def check_token(self) -> Optional[bool]:
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

    async def login_with_aim(self,
                             aim_host: str = None,
                             appid: str = None,
                             username: str = None,
                             cert_file: str = None,
                             cert_key: str = None,
                             root_ca: Optional[ Union[bool, str] ] = None,
                             *,     # From this point all parameters are keyword only
                             timeout: int = None,
                             max_concurrent_tasks: int = None,
                             user_search: dict = None,
                             auth_type=None,
                             cert_passphrase=None,
                             verify: Optional[ Union[bool, str] ] = None):
        """ Authenticate the PVWA user using AIM interface to get password (secret) in CyberArk.

        We only support client certificate authentication to the AIM.


        | ℹ️ The following parameters are optional. If a parameter is not set, it will be obtained
            from *EPV* initialization (configuration file or serialization).

        | ⚠️ Any specified parameter from the *login_with_aim* function will override the *EPV_AIM*
            definition.


        * The function parameter behavoir toward login initialization (configuration: file or serialization):
            * If a parameter is set:
                * an AIM session is not open:
                    * the AIM configuration (EPV.AIM) is modifed
                * an AIM session is open and the value is different from AIM configuration (EPV.AIM)
                    * a error will be raise
            * If a parameter is not set:
                *  it will be obtained from AIM configuration (EPV.AIM)

        :param aim_host: *AIM* CyberArk host
        :param appid: *AIM* Application ID
        :param auth_type: *PVWA* logon authenticafication method: CyberArk, Windows, LDAP or Radius
        :param cert_file: *AIM* Filename public certificat
        :param cert_key: *AIM* Filename private key certificat
        :param cert_passphrase: *AIM* Certificat password
        :param max_concurrent_tasks: *AIM* Maximum number of parallel task (default 10)
        :param timeout: *AIM* Maximum wait time in seconds before generating a timeout (default 30 seconds)
        :param username: *PVWA* Name of the user who is logging in to the Vault (PVWA username)
        :param verify: *AIM* Directory or filename of the ROOT certificate authority (CA)
        :type user_search: Dictionary
        :param user_search: *PVWA* Search parameters to uniquely identify the PVWA user (optional).

        |     **user_search** dictionary may define any of the following keys:
        |         safe, object, folder, address, database, policyid, failrequestonpasswordchange.
        |         We recommend, if necessary, **safe** and **object** keys to uniquely identify
                  the PVWA user.  Refer to  `CyberArk Central Credential Provider - REST web service`_.

        :raise GetTokenException: Logon error
        :raise AiobastionException: AIM configuration setup error
        :raise CyberarkException: Runtime error
        """
        # For compatibility with older versions
        if verify is not None and root_ca is not None and verify != root_ca:
            raise AiobastionException("You can't specify both parameters: 'verify' and 'root_ca'.")

        if root_ca is not None:
            verify = root_ca
            root_ca = None

        # Is AIM attribute defined ?
        if self.AIM:
            # If AIM session is not active, it is not too late to change the default configuration
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
                if verify is not None:
                    self.AIM.verify = verify
                if timeout:
                    self.AIM.timeout = timeout
                if max_concurrent_tasks:
                    self.AIM.max_concurrent_tasks = max_concurrent_tasks
                if cert_passphrase:
                    self.AIM.passphrase = cert_passphrase

                # Valide AIM setup
                self.AIM.validate_and_setup_aim_ssl()

            # Complete undefined parameters with AIM and PVWA attributes
            aim_host = (aim_host or self.AIM.host)
            appid = (appid or self.AIM.appid)
            cert_file = (cert_file or self.AIM.cert)
            cert_key = (cert_key or self.AIM.key)
            cert_passphrase = (cert_passphrase or self.AIM.passphrase)
            max_concurrent_tasks = (max_concurrent_tasks or self.AIM.max_concurrent_tasks or self.max_concurrent_tasks)
            timeout = (timeout or self.AIM.timeout or self.timeout)

            if verify is None:   # May be false
                if self.AIM.verify is not None:
                    verify = self.AIM.verify
                else:
                    if self.verify is not None:
                        verify = self.verify  # PVWA
                    else:
                        verify = Config.CYBERARK_DEFAULT_VERIFY

            if (aim_host and aim_host != self.AIM.host) or \
               (appid and appid != self.AIM.appid) or \
               (cert_file and cert_file != self.AIM.cert) or \
               (cert_key and cert_key != self.AIM.key) or \
               (verify is not None and verify != self.AIM.verify) or \
               (cert_passphrase and  cert_passphrase != self.AIM.passphrase):
                raise CyberarkException("AIM is already initialized ! Please close EPV before reopen it.")
        else:
            # AIM is not defined
            if verify is None:
                if self.verify is not None:
                    verify = self.verify  # PVWA
                else:
                    verify = Config.CYBERARK_DEFAULT_VERIFY

            # keep_cockies is not handled
            self.AIM = EPV_AIM(appid=appid, cert=cert_file, host=aim_host, key=cert_key, max_concurrent_tasks=max_concurrent_tasks,
                               passphrase=cert_passphrase, timeout=timeout, verify=verify)

            # Valid AIM setup
            self.AIM.validate_and_setup_aim_ssl()

        # Check mandatory attributs
        if self.AIM.host is None or \
           self.AIM.appid is None or \
           self.AIM.cert is None:
            raise AiobastionException(
                "Missing AIM mandatory parameters: host, appid, cert.")

        # Complete undefined parameters with PVWA attributes
        if username is None and self.username:
            username = self.username

        if username is None:
            raise AiobastionException(
                "Username must be provided on login_with_aim call or in configuration file.")

        if  user_search is None and self.user_search:
            user_search = self.user_search

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
            if self.username is None:
                raise AiobastionException(
                    "Username must be provided on login call or in configuration file."
                    " You may also configure the AIM section.")
            username = self.username

        if not auth_type:
            if self.authtype:
                auth_type = self.authtype
            else:
                auth_type = "cyberark"

        self.validate_and_setup_ssl()

        if self.AIM and self.AIM.handle_aim_request is None:
            self.AIM.validate_and_setup_aim_ssl()

        if password is None:
            if self.password is not None:
                password = self.password
                self.password = None
            else:
                if not self.AIM:
                    raise AiobastionException(
                        "Password must be provided on login call or in configuration file."
                        " You may configure the AIM section or call the login_with_aim function.")

                # Valide AIM setup
                self.AIM.validate_and_setup_aim_ssl()

                params = {"UserName": username}

                if user_search is None:
                    if self.user_search:
                        user_search = self.user_search

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
        finally:
            # update or clean the session
            await self.close_session()

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
            self.session = aiohttp.ClientSession(headers=head, cookies = self.cookies)
            self.logger.debug(f"Building session ID (token is known) : {self.session}")

        elif self.session.closed:
            # This should never happen, but it's a security in case of unhandled exceptions
            self.logger.debug("Never happens scenario happened (Session closed but not None)")
            head = {'Content-type': 'application/json',
                    'Authorization': self.__token}
            self.session = aiohttp.ClientSession(headers=head, cookies = self.cookies)


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
        serialized = {}

        # EPV attributes
        for attr_name in EPV._SERIALIZED_FIELDS_OUT:
            if attr_name == "token":
                serialized[attr_name] = self.__token
            else:
                serialized[attr_name] = getattr(self, attr_name, None)


        # options modules
        if self.AIM:
            serialized["AIM"] = self.AIM.to_json()

        d = self.account.to_json()
        if d:
            serialized["account"] = self.account.to_json()

        d = self.accountgroup.to_json()
        if d:
            serialized["accountgroup"] = self.accountgroup.to_json()

        d = self.application.to_json()
        if d:
            serialized["application"] = self.application.to_json()

        d = self.group.to_json()
        if d:
            serialized["group"] = self.group.to_json()

        d = self.platform.to_json()
        if d:
            serialized["platform"] = self.platform.to_json()

        d = self.safe.to_json()
        if d:
            serialized["safe"] = self.safe.to_json()

        d = self.session_management.to_json()
        if d:
            serialized["session_management"] = self.session_management.to_json()

        d = self.system_health.to_json()
        if d:
            serialized["system_health"] = self.system_health.to_json()

        d = self.user.to_json()
        if d:
            serialized["user"] = self.user.to_json()

        d = self.utils.to_json()
        if d:
            serialized["utils"] = self.utils.to_json()

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
        Function that handles requests to the API. This is a low-level function, and you most likely wouldn't need to
        call it. If you do, there is the opportunity to enhance other modules.
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
                else:
                    if req.status == 404:
                        raise CyberarkException(f"404 error with URL {url}")
                    elif req.status == 401:
                        raise CyberarkException("You are not logged, you need to login first")
                    elif req.status == 405:
                        raise CyberarkException("Your PVWA version does not support this function")
                    try:
                        content = await req.json(content_type=None)
                        self.logger.debug(f"Content => {content}")
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
