import asyncio
import copy
import json
import os
import ssl
from collections import namedtuple
from http import HTTPStatus
from typing import Union, Tuple, Optional

import aiohttp
from aiohttp import ContentTypeError

from .exceptions import AiobastionException, CyberarkException, CyberarkAPIException, CyberarkAIMnotFound, AiobastionConfigurationException
from .config import Config, validate_integer
# from .cyberark import EPV

# AIM section
AIM_secret_resp = namedtuple('AIM_secret_resp', ['secret', 'detail'])


class EPV_AIM:
    """
    Class managing communication with the Central Credential Provider (AIM) GetPassword Web Service
    """
    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS_IN = [
        "appid",
        "cert",
        "host",
        "key",
        "max_concurrent_tasks",
        "passphrase",
        "timeout",
        "verify",
        ]

    # List of attributes for serialization (to_json)
    _SERIALIZED_FIELDS_OUT = [
        "appid",
        "cert",
        "host",
        "key",
        "max_concurrent_tasks",
        # "passphrase",     # Exclude
        "timeout",
        "verify",
        ]

    # List of attributes for user_search available in AIM
    _GETPASSWORD_REQUEST_PARM = [
        "address",
        "connectiontimeout",
        "database",
        "failrequestonpasswordchange",
        "folder",
        "object",
        "policyid",
        "query",
        "queryformat",
        "reason",
        "safe",
        "username",
        ]

    # You must specify the following parameters by key=value (no positional parameters allowed):
    def __init__(self, *,
                 appid: Optional[str] = None,
                 cert: Optional[str] = None,
                 host: Optional[str] = None,
                 key: Optional[str] = None,
                 max_concurrent_tasks: int = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS,
                 passphrase: Optional[str] = None,
                 serialized: Optional[dict] = None,
                 timeout: int = Config.CYBERARK_DEFAULT_TIMEOUT,
                 verify: Optional[Union[str, bool]] = None,
                 ):

        self.appid = appid
        self.cert = cert
        self.host = host
        self.key = key
        self.max_concurrent_tasks = max_concurrent_tasks
        self.passphrase = passphrase
        self.timeout = timeout
        self.verify = verify if verify is not None else Config.CYBERARK_DEFAULT_VERIFY

        # Session management
        self.__sema = None
        self.session = None
        self.request_params = None

        if serialized:
            for k, v in serialized.items():
                keyname = k.lower()
                if keyname in EPV_AIM._SERIALIZED_FIELDS_IN:
                    setattr(self, keyname, v)
                else:
                    raise AiobastionException(f"Unknown serialized AIM field: {k} = {v!r}")

        # Optional attributes
        if self.timeout is None:
            self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT

        if self.max_concurrent_tasks is None:
            self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS

        if self.verify is not None and not (isinstance(self.verify, str) or isinstance(self.verify, bool)):
            raise AiobastionException(
                f"Invalid type for parameter 'verify' in AIM: {type(self.verify)} value: {self.verify!r}")

        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionConfigurationException(
                    f"CA certificat File not found {self.verify!r} (Parameter 'verify' in AIM).")


    @classmethod
    def validate_class_attributes(cls, serialized: dict, section: str, epv,  configfile: Optional[str] = None) -> dict:
        """validate_class_attributes      Initialize and validate the EPV_AIM definition (file configuration and serialized)

        Arguments:
            serialized {dict}           Definition from configuration file or serialization
            section {str}               verified section name

        Keyword Arguments:
            epv {EPV}                   EPV class definition
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Information:
            "appid":                # Default = Connection (appid)
            "cert":
            "host":                 # Default = PVWA (host)
            "key":
            "max_concurrent_tasks": # Default = PVWA (max_concurrent_tasks) or Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
            "passphrase":
            "timeout":              # Default = PVWA (timeout) or Config.CYBERARK_DEFAULT_TIMEOUT
            "verify":               # Default = PVWA (PVWA_CA) or Config.CYBERARK_DEFAULT_VERIFY

        Returns:
            new_serialized {dict}       AIM defintion
        """
        if configfile:
            _config_source = configfile
        else:
            _config_source = "serialized"

        new_serialized = {}

        for k in serialized.keys():
            keyname = k.lower()

            # Special validation: integer, boolean
            if keyname in ["max_concurrent_tasks", "timeout"]:
                if serialized[k] is not None:
                    new_serialized[keyname] = validate_integer(_config_source, f"{section}/{keyname}", serialized[k])
            elif keyname in ["verify"]:
                if serialized[k] is not None:
                    if isinstance(serialized[k], str) or isinstance(serialized[k], bool):
                        new_serialized["verify"] = serialized[k]
                    else:
                        raise AiobastionConfigurationException(
                            f"Parameter type invalid '{section}/{k}' "
                            f"in {_config_source}: {serialized[k]!r}")

            elif keyname in EPV_AIM._SERIALIZED_FIELDS_IN:
                # String definition
                if serialized[k] is not None:
                    new_serialized[keyname] = serialized[k]
            else:
                # Unknown attribute
                raise AiobastionConfigurationException(f"Unknown attribute in section '{section}' from {_config_source}: {k} is unknown.")



        # Complete initialization with epv section (file configuration and serialized)
        if epv:
            if "host" not in new_serialized and epv.api_host:
                new_serialized["host"]  = epv.api_host

            # Should not be None or the default value
            if "timeout" not in new_serialized and epv.timeout and \
               epv.timeout != Config.CYBERARK_DEFAULT_TIMEOUT:
                new_serialized["timeout"] = epv.timeout

            # Should not be None or the default value
            if "max_concurrent_tasks" not in new_serialized and \
                epv.max_concurrent_tasks is not None  and \
                epv.max_concurrent_tasks != Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS:
                new_serialized["max_concurrent_tasks"] =  epv.max_concurrent_tasks

            # Should not be None or the default value
            if "verify" not in new_serialized and \
               epv.verify is not None and \
               epv.verify != Config.CYBERARK_DEFAULT_VERIFY:
                new_serialized["verify"] = epv.verify

        # If no value has been set, return a empty dictionary. AIM should not be set.
        if not any(new_serialized.values()):
            return {}

        # Default values if not set
        new_serialized.setdefault("max_concurrent_tasks", Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS)
        new_serialized.setdefault("timeout", Config.CYBERARK_DEFAULT_TIMEOUT)
        new_serialized.setdefault("verify", Config.CYBERARK_DEFAULT_VERIFY)

        # Validation
        if isinstance(new_serialized["verify"], str):
            if not os.path.exists(new_serialized["verify"]):
                raise AiobastionConfigurationException(
                    f"CA certificat File not found {new_serialized['verify']!r} (Parameter 'verify' in AIM).")

        return new_serialized

    def validate_and_setup_aim_ssl(self):
        if self.session:
            return

        # Check mandatory attributes
        if self.host is None or \
           self.appid is None or \
           self.cert is None:
            raise AiobastionException(f"Missing AIM mandatory parameters. "
                                       "Required parameters are: host, appid, cert.")

        if not os.path.exists(self.cert):
            raise AiobastionException(f"Parameter 'cert' in AIM: Public certificate file not found: {self.cert!r}")

        if self.key and not os.path.exists(self.key):
            raise AiobastionException(f"Parameter 'key' in AIM: Private key certificat file not found: {self.key!r}")

        # Set verify if it is not set
        if self.verify is None:
            self.verify = Config.CYBERARK_DEFAULT_VERIFY

        if not (isinstance(self.verify, str) or isinstance(self.verify, bool)):
            raise AiobastionException(
                f"Invalid type for parameter 'verify' in AIM: {type(self.verify)} value: {self.verify!r}")

        if (isinstance(self.verify, str) and not os.path.exists(self.verify)):
            raise AiobastionException(f"Parameter 'verify' in AIM: file not found {self.verify!r}")

        if isinstance(self.verify, str):
            if not os.path.exists(self.verify):
                raise AiobastionException(f"Parameter 'verify' in AIM: file not found {self.verify!r}")

            if os.path.isdir(self.verify):
                ssl_context = ssl.create_default_context(capath=self.verify)
            else:
                ssl_context = ssl.create_default_context(cafile=self.verify)
        else:  # True or False
            ssl_context = ssl.create_default_context()

            if not self.verify:  # False
                ssl_context.check_hostname = False

        # if self.key is None:
        #     ssl_context.load_cert_chain(self.cert, keyfile=self.key, password=self.passphrase)
        # else:
        ssl_context.load_cert_chain(self.cert, keyfile=self.key, password=self.passphrase)

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

                if key_lower not in EPV_AIM._GETPASSWORD_REQUEST_PARM:
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
                self.validate_and_setup_aim_ssl()

            self.session = session

    def to_json(self):
        serialized = {}

        for attr_name in EPV_AIM._SERIALIZED_FIELDS_OUT:
            serialized[attr_name] = getattr(self, attr_name, None)

        return serialized

    def get_url(self, url) -> Tuple[str, dict]:
        addr = f"https://{self.host}/AIMWebService/api/{url}"
        head = {"Content-type": "application/json"}

        return addr, head

    # Context manager
    async def __aenter__(self):
        self.get_aim_session()

        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close_aim_session()

    def get_aim_session(self):
        if self.session is None:
            if self.request_params is None:
                self.validate_and_setup_aim_ssl()
                # Previously we tried to use aiohttp session,
                # but now we are always doing our own session for AIM
                # TODO: test this with aiohttp.ClientSession(cookies = self.cookies)
            self.session = aiohttp.ClientSession()

        if self.__sema is None:
            self.__sema = asyncio.Semaphore(self.max_concurrent_tasks)

        return self.session

    async def close_aim_session(self):
        try:
            if self.session:
                # Are we using the epv.session, if so don't close it
                # if self.epv is None or self.epv.session is None or \
                #         (self.epv.session and self.epv.session != self.session):
                await self.session.close()
        except (CyberarkException, AttributeError):
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
        """ Retrieve the secret from the GetPassword Web Service Central Credential Provider (AIM)

        | ℹ️ The following parameters are optional searchable keys. Refer to
            `CyberArk Central Credential Provider - REST web service`.

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
        :param failrequestonpasswordchange: Boolean, Whether an error will be returned if
            this web service is called when a password change process is underway or not.
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

        detail_info = await self.handle_aim_request("get", "Accounts", params=kwargs)
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

    async def handle_aim_request(self, method: str, short_url: str, params: dict = None, filter_func=lambda x: x):
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
        session = self.get_aim_session()

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
                        print(await req.text())
                        details = EPV_AIM.handle_error_detail_info(url, params_new)
                        raise CyberarkException(
                            f"HTTP error {req.status}: {str(err)} || Additional Details : {details}") from err

            except aiohttp.ClientError as err:
                details = EPV_AIM.handle_error_detail_info(url, params_new)
                raise CyberarkException(f"HTTP error: {str(err)} || Additional Details : {details}") from err
