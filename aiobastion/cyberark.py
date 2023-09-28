# -*- coding: utf-8 -*-
import os.path
import asyncio
import json
import ssl
from typing import Tuple
import copy

import aiohttp
from aiohttp import ContentTypeError
from http import HTTPStatus
from collections import namedtuple

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
        # AIM Communication
        self.AIM       = None
        self.cpm       = ""
        self.config    = None
        self.verify    = False

        if configfile is None and serialized is None:
            raise AiobastionException("You must provide either configfile or serialized to init EPV")
        if configfile is not None and serialized is not None:
            raise AiobastionException("You must provide either configfile or serialized to init EPV, not both")

        if configfile is not None:
            self.config = Config(configfile)

            if self.config.PVWA_CA is not False:
                if not os.path.exists(self.config.PVWA_CA):
                    raise AiobastionException(f"Parameter 'CA' (or 'verify') in PVWA: file not found {self.config.PVWA_CA!r}")

                self.request_params = {"timeout": self.config.timeout,
                                       "ssl": ssl.create_default_context(cafile=self.config.PVWA_CA)}
                self.verify = self.config.PVWA_CA
            else:
                self.request_params = {"timeout": self.config.timeout, "ssl": False}

            self.api_host = self.config.PVWA
            self.authtype = self.config.authtype
            self.cpm = self.config.CPM
            self.retention = self.config.retention
            self.max_concurrent_tasks = self.config.max_concurrent_tasks
            self.timeout = self.config.timeout
            self.__token = token

            # AIM Communication
            if self.config.AIM is not None:
                self.AIM = EPV_AIM(epv=self, **self.config.AIM)

        if serialized is not None:
            self.epv_serialize(serialized)

            # AIM Communication
            if "AIM" in serialized:
                serialized_aim = copy.copy(serialized["AIM"])

                serialized_aim.setdefault("host",                 getattr(self, "api_host",    None))
                serialized_aim.setdefault("max_concurrent_tasks", getattr(self, "max_concurrent_tasks", Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS))
                serialized_aim.setdefault("timeout",              getattr(self, "timeout", Config.CYBERARK_DEFAULT_TIMEOUT))
                serialized_aim.setdefault("verify",               getattr(self, "verify",  False))

                self.AIM = EPV_AIM(epv=self, serialized=serialized["AIM"])


        # self.session = requests.Session()

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

    def epv_serialize(self, serialized):
        if not isinstance(serialized, dict):
            raise AiobastionException(f"Type error: Parameter 'serialized' must be a dictionary.")

        # Validate dictionary key
        for k in serialized.keys():
            if k not in [
                     "AIM"
                    ,"api_host"
                    ,"authtype"
                    ,"cpm"
                    ,"max_concurrent_tasks"
                    ,"retention"
                    ,"timeout"
                    ,"token"
                    ,"verify"
                    ]:
                raise AiobastionException(f"Unknown serialized field: {k} = {serialized[k]!r}")

        if "timeout" in serialized:
            self.timeout = serialized["timeout"]
        else:
            self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT

        if "verify" in serialized:
            self.verify = serialized["verify"]

            if self.verify is not False:
                if not os.path.exists(self.verify):
                    raise AiobastionException(f"Parameter 'verify' (or 'CA') in serialized: file not found {self.verify!r}")

                self.request_params = {"timeout": self.timeout,
                                        "ssl": ssl.create_default_context(cafile=self.verify)}
            else:
                self.request_params = {"timeout": self.timeout, "ssl": False}
        else:
            self.verify = False
            self.request_params = {"timeout": Config.CYBERARK_DEFAULT_TIMEOUT, "ssl": self.verify}

        if "api_host" in serialized:
            self.api_host = serialized['api_host']
        else:
            # raise AiobastionException("Missing EPV mandatory parameter in serialized: 'api_host'.")
            self.api_host = None

        if "authtype" in serialized:
            self.authtype = serialized["authtype"]
        else:
            self.authtype = None

        if "cpm" in serialized:
            self.cpm = serialized['cpm']
        else:
            self.cpm = ""
        if "retention" in serialized:
            self.retention = serialized['retention']
        else:
            self.retention = Config.CYBERARK_DEFAULT_RETENTION
        if "max_concurrent_tasks" in serialized:
            self.max_concurrent_tasks = serialized['max_concurrent_tasks']
        else:
            self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
        if "token" in serialized:
            self.__token = serialized['token']
        else:
            self.__token = None


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
                    except Exception as err:
                        error = f"Unable to get error message {err}"
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


    async def login_with_aim(self, aim_host: str, appid: str, username: str, cert_file: str, cert_key: str, root_ca=False, timeout: int = Config.CYBERARK_DEFAULT_TIMEOUT, max_concurrent_tasks: int = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS, user_search: dict = None, auth_type=""):
        # Is it a new AIM ?
        if self.AIM:
            if (aim_host            and aim_host  != self.AIM.host)  or \
               (appid               and appid     != self.AIM.appid) or \
               (cert_file           and cert_file != self.AIM.cert)  or \
               (cert_key            and cert_key  != self.AIM.key)   or \
               (root_ca is not None and root_ca   != self.AIM.verify):
                raise CyberarkException("AIM is already initialized ! Please close EPV before reopen it.")
        else:
            self.AIM = EPV_AIM(epv=self, host=aim_host, appid=appid, cert=cert_file, key=cert_key, verify=root_ca, timeout=timeout, max_concurrent_tasks=max_concurrent_tasks)

        try:
            await self.login(username=username, password=None, auth_type=auth_type, user_search=user_search)

        except CyberarkException as err:
            raise GetTokenException(str(err))

    async def login(self, username=None, password=None, auth_type="", user_search=None):
        if await self.check_token():
            return

        if self.api_host is None:
            raise AiobastionException("Host must be provided in configuration file or in EPV(serialized={'api_host: 'cyberark-host'}).")

        if username is None:
            if self.config is None or self.config.username is None:
                raise AiobastionException("Username must be provided on login call or in configuration file. Or you must configure the AIM section.")
            username = self.config.username

        if password is None:
            if self.config and self.config.password:
                password = self.config.password
            else:
                if not self.AIM:
                    raise AiobastionException("Password must be provided on login call or in configuration file. Or you must configure the AIM section.")

                params = {"UserName": username}

                if user_search is None:
                    if self.config and self.config.user_search:
                        user_search = self.config.user_search

                if user_search:
                    err = EPV_AIM.valide_secret_params(user_search)

                    if err:
                        raise GetTokenException(f"invalid parameter in 'user_search' {err}")

                    params.update(user_search)

                try:
                    # Get password form AIM
                    password = await self.AIM.get_secret(**params)
                except (CyberarkAIMnotFound, CyberarkAPIException, CyberarkException) as err:
                    raise GetTokenException(str(err))

        if auth_type == "":
            if self.authtype:
                auth_type = self.authtype
            else:
                auth_type = "Cyberark"

        try:
            self.__token = await self.__login_cyberark(username, password, auth_type)
            # update the session
            await self.close_session()
        except ChallengeResponseException:
            # User should enter passcode now
            raise

        except CyberarkException as err:
            raise GetTokenException(str(err))

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
            serialized["AIM"]  = self.AIM.to_json()

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
            async with session.request(method, url, json=data, headers=head, params=params, **self.request_params) as req:
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
                        except:
                            raise
                else:
                    if req.status == 404:
                        raise CyberarkException(f"404 error with URL {url}")
                    elif req.status == 401:
                        raise CyberarkException(f"You are not logged, you need to login first")
                    elif req.status == 405:
                        raise CyberarkException("Your PVWA version does not support this function")
                    try:
                        content = await req.json(content_type=None)
                    except (KeyError, ValueError, ContentTypeError):
                        raise CyberarkException(f"Error with Cyberark status code {str(req.status)}")

                    if "Details" in content:
                        details = content["Details"]
                    else:
                        details = ""

                    if "ErrorCode" in content and "ErrorMessage" in content:
                        raise CyberarkAPIException(req.status, content["ErrorCode"], content["ErrorMessage"], details)
                    else:
                        raise CyberarkAPIException(req.status, "NO_ERR_CODE", content)
            # except Exception as err:
            #     raise CyberarkException(err)

# AIM section
AIM_secret_resp = namedtuple('AIM_secret_resp', ['secret', 'detail'])

class EPV_AIM:
    _serialized_fields = ["host", "appid", "cert", "key", "verify", "timeout", "max_concurrent_tasks" ]
    _getPassword_request_parm = [ "safe", "folder", "object",  "username", "address", "database"
                          ,"policyid", "reason",  "connectiontimeout", "query", "queryformat", "failrequestonpasswordchange" ]

    """
    Class managing communication with the Central Credential Provider (AIM) GetPassword Web Service
    """
    def __init__(self, host: str = None, appid: str = None, cert: str = None
                ,key: str = None, verify: str = None, timeout: int = Config.CYBERARK_DEFAULT_TIMEOUT, max_concurrent_tasks: int = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS, serialized:dict = None, epv: EPV = None):


        self.host    = host
        self.appid   = appid
        self.cert    = cert
        self.key     = key
        self.verify  = verify
        self.timeout = timeout
        self.max_concurrent_tasks = max_concurrent_tasks

        # Session management
        self.epv = epv
        self.__sema = None
        self.session = None

        if serialized:
            for k,v in serialized.items():
                keyname = k.lower()
                if keyname in EPV_AIM._serialized_fields:
                    setattr(self, keyname, v)
                else:
                    raise AiobastionException(f"Unknown serialized AIM field: {k} = {v!r}")

        # Check mandatory attributs
        if self.host  is None or \
           self.appid is None or \
           self.cert  is None or \
           self.key   is None:
            raise AiobastionException("Missing AIM mandatory parameters: host, appid, cert, key (and a optional verify).")

        # Optional attributs
        if self.timeout is None:
            self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT

        if self.max_concurrent_tasks is None:
            self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS

        # Prepare AIM communication
        if self.verify:
            if not os.path.exists(self.verify):
                raise AiobastionException(f"Parameter 'verify' in AIM: file not found {self.verify!r}")

            if not os.path.exists(self.cert):
                raise AiobastionException(f"Parameter 'cert' in AIM: file not found: {self.cert!r}")

            if not os.path.exists(self.key):
                raise AiobastionException(f"Parameter 'key' in AIM: file not found: {self.key!r}")

            ssl_context = ssl.create_default_context(cafile=self.verify)
            ssl_context.load_cert_chain(self.cert, self.key)
        else:
            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(self.cert, self.key)

        self.request_params =  \
            {"timeout": self.timeout,
             "ssl"    : ssl_context}


    @staticmethod
    def valide_secret_params(params: dict = None) -> str:
        is_valid_ind = True
        error_str= ""

        if not isinstance(params, dict):
            is_valid_ind = False
            error_str = "parameter is not a dictionary"
        else:
            for k in params:
                key_lower = k.lower()

                if key_lower not in EPV_AIM._getPassword_request_parm:
                    is_valid_ind = False
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
            if self.epv.session:
                self.session = self.epv.session
            else:
                self.session = aiohttp.ClientSession()

        if self.__sema is None:
            # This statement is wrong:
            #    if self.epv.__sema:
            #        self.__sema = self.epv.__sema
            if self.epv._EPV__sema:
                self.__sema = self.epv._EPV__sema
            else:
                self.__sema = asyncio.Semaphore(self.max_concurrent_tasks)

        return self.session

    async def close_session(self):
        try:
            if self.session:
                # Are we using the epv.session, if so don't close it
                if self.epv.session is None or (self.epv.session and self.epv.session != self.session):
                    await self.session.close()
        except (CyberarkException, AttributeError):
            pass
        self.session = None
        self.__sema = None


    async def get_secret(self, **kwargs):
        """
        This function allow to search using one or more parameters and return list of address id
        :param kwargs: any searchable key = value
                  like:  UserName, Safe, Folder, Object (which is name), Address, Database, PolicyID, Reason, Query, QueryFormat, FailRequestOnPasswordChange, ...
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
        :param kwargs: any searchable key = value
                  keys:  username, safe, folder, object, address, database, policyid, reason, Query, ...
        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Execution error
        :return:  namedtuple of (secret, detail) or None
            secret = password
            detail = dictionary from the Central Credential Provider (AIM) GetPassword Web Service
        """

        detail_info = await self.handle_request("get", "Accounts", params=kwargs)
        secret_detail = AIM_secret_resp(detail_info["Content"], detail_info)

        return secret_detail

    @staticmethod
    def handle_error_detail_info(url: str = None, params: dict = None):
        # Mask the appid attribut, if you are a security maniac
        if "appid" in params:
            params_copy = copy.copy(params)
            params_copy["appid"] = "<hidden>"
        else:
            params_copy = params

        return f"url: {url}, params: {params_copy}"

    async def handle_request(self, method: str, short_url: str, data=None, params: dict = None, filter_func=lambda x: x):
        """
        Function that handles AIM requests to the API
        :param method: "get"
        :param params: dictonary parameters for CyberArk like Safe, Object, UserName, Address, Reason, Query, ...
        :param short_url: piece of URL after AIMWebService/api/
        :param filter_func:
        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Execution error
        :return: dictonary return by CyberArk
        """
        assert method.lower() == "get"

        url, head = self.get_url(short_url)
        session = self.get_session()
        params.setdefault('appid', self.appid)

        async with self.__sema:
            async with session.request(method, url, headers=head, params=params, **self.request_params) as req:
                # if req.status == 404:
                #     raise CyberarkException(f"Error 404 : Endpoint {url} not found")

                try:
                    resp_json = await req.json()
                    if req.status == 200:
                        if "Content" not in resp_json:
                            raise CyberarkAPIException(req.status, "INVALID_JSON", "Could not find the password ('Content')" , EPV_AIM.handle_error_detail_info(url, params))

                        return filter_func(resp_json)
                    else:
                        # This is a error
                        if "Details" in resp_json:
                            details = resp_json["Details"]
                        else:
                            details =  EPV_AIM.handle_error_detail_info(url, params)

                        if "ErrorCode" in resp_json and "ErrorMsg" in resp_json:
                            if resp_json["ErrorCode"] == "APPAP004E":
                                raise CyberarkAIMnotFound(req.status, resp_json["ErrorCode"], resp_json["ErrorMsg"], details)
                            else:
                                raise CyberarkAPIException(req.status, resp_json["ErrorCode"], resp_json["ErrorMsg"], details)
                        else:
                            http_error = HTTPStatus(req.status)

                            raise CyberarkAPIException(req.status, "HTTP_ERR_CODE", http_error.phrase, details)
                except (KeyError, ValueError, ContentTypeError) as err:
                    #http_error = HTTPStatus(req.status)
                    details = EPV_AIM.handle_error_detail_info(url, params)
                    raise CyberarkException(f"HTTP error {req.status}: {str(err)} || Additional Details : {details}")
