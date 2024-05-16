<<<<<<< HEAD
# -*- coding: utf-8 -*-
import asyncio
import re
from typing import List, Union, AsyncIterator

import aiohttp

from .config import validate_ip, flatten, validate_integer
from .exceptions import (
    CyberarkAPIException, CyberarkException, AiobastionException, CyberarkAIMnotFound, AiobastionConfigurationException
)

BASE_FILECATEGORY = ("platformId", "userName", "address", "name")
SECRET_MANAGEMENT_FILECATEGORY = ("automaticManagementEnabled", "manualManagementReason", "lastModifiedTime",
                                  "lastReconciledTime", "lastVerifiedTime", "status")


class PrivilegedAccount:
    """Base class to be used with accounts fonctions"""

    def __init__(self, name: str, platformId: str, safeName: str,
                 platformAccountProperties: dict = None, secret: str = "", secretType: str = None,
                 secretManagement: dict = None,
                 remoteMachinesAccess: dict = None,
                 id: str = "", address: str = "", userName: str = "",
                 **other):
        self.secret = secret
        if remoteMachinesAccess is not None:
            if not all([k in ["remoteMachines", "accessRestrictedToRemoteMachines"]
                        for k in remoteMachinesAccess.keys()]):
                raise AiobastionException("remoteMachinesAccess is not a valid dictionary")
        if secretManagement is None:
            secretManagement = {"automaticManagementEnabled": True, "manualManagementReason": ""}
        self.remoteMachinesAccess = remoteMachinesAccess
        self.secretManagement = secretManagement
        self.secretType = secretType
        if secretType not in [None, "password", "key"]:
            raise AiobastionException("secretType is not valid")
        if platformAccountProperties is None:
            platformAccountProperties = {}
        self.platformAccountProperties = platformAccountProperties
        self.safeName = safeName
        self.platformId = platformId
        self.userName = userName
        self.address = address
        self.name = name
        self.id = id
        for k, v in other.items():
            setattr(self, k, v)

    def get_name(self):
        """ Get a default name of a Privileged Account

        :return: address-username of the PrivilegedAccount
        """
        return f"{self.address}-{self.userName}"

    def to_json(self):
        """
        Convert the PrivilegedAccount object to a python dict object

        :return: A JSON ready to use object
        """
        json_object = {"id": self.id, "name": self.name, "address": self.address, "userName": self.userName,
                       "platformId": self.platformId, "safeName": self.safeName, "secret": self.secret,
                       "platformAccountProperties": self.platformAccountProperties,
                       "secretManagement": self.secretManagement}
        if self.remoteMachinesAccess is not None:
            json_object["remoteMachinesAccess"] = self.remoteMachinesAccess
        if self.secretType is not None:
            json_object["secretType"] = self.secretType

        return json_object

    def to_dict(self):
        """
        Convert the PrivilegedAccount object to a python dict object

        :return: a dict
        """
        return self.to_json()

    def __str__(self):
        strrepr = self.to_json()
        return str(strrepr)

    # Mapping Protocol
    def __iter__(self):
        for key, value in self.to_dict():
            yield key, value

    def keys(self):
        return list(self.to_dict().keys())

    def items(self):
        return list(self.to_dict().items())

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __eq__(self, other):
        # Check by ID is the best way
        if self.id != "" and other.id != "":
            return self.id == other.id
        # Else we check by name and safeName (Cyberark prevent different objects to have the same name in the same safe)
        else:
            return (self.safeName == other.safeName) and (self.name == other.name)

        # return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        # Check by ID is the best way
        if self.id != "" and other.id != "":
            return self.id != other.id
        # Else we check by name and safeName (Cyberark prevents object to have the same name in the same safe)
        else:
            return (self.safeName != other.safeName) or (self.name != other.name)

    # End of mapping Protocol


    def __repr__(self):
        # For Debugging, short account identification
        s = f"<{self.__class__.__name__} {hex(id(self))}:"

        for attr in ["id", "name", "safeName"]:
            v = getattr(self, attr, None)
            if v:
                s += f" {attr}={v}"

        s += ">"

        return s

    def cpm_status(self):
        """
        Get the CPM Status of an account

        :return: "success" "failure "Deactivated" or "No status (yet)"
        """
        if "status" in self.secretManagement:
            # 'success' or 'failure'
            return self.secretManagement["status"]
        elif "automaticManagementEnabled" in self.secretManagement and \
                not self.secretManagement["automaticManagementEnabled"]:
            return "Deactivated"
        else:
            return "No status (yet)"

    def last_modified(self, days=True):
        """
        Get the last modified time of an PrivilegedAccount secret

        :param days: Indicates if the return must be a timestamp or a number of days (default)
        :return: The timestamp or the number of days since last change
        """
        import time
        if "lastModifiedTime" in self.secretManagement:
            ts = self.secretManagement["lastModifiedTime"]
            if days:
                return int((int(time.time()) - ts) / 86400)
            else:
                return ts


def _filter_account(account: dict, filters: dict):
    """
    This function helps to ensure that search accounts match with requested accounts

    :param account: one json CyberArk repr of a privileged address
    :param filters: one dict like username: admin
    :return: check if content of privileged FC is exactly the content of the filter
    """
    for k, v in filters.items():
        if k.lower() == "username":
            if "userName" not in account:
                return False
            if account['userName'].upper() != v.upper():
                return False
        elif k.lower() == "address":
            if account['address'].upper() != v.upper():
                return False
        elif k.lower() in ("platform", "platformid"):
            if account['platformId'].upper() != v.upper():
                return False
        elif k.lower() == "name":
            if account['name'].upper() != v.upper():
                return False
        elif k not in account['platformAccountProperties']:
            return False
        elif account['platformAccountProperties'][k] != v:
            return False
    return True


class Account:
    """
    Utility class to handle account manipulation
    """
    _ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX = 2
    _ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX = 3

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = ["logon_account_index",
                          "reconcile_account_index"]


    def __init__(self, epv, logon_account_index = None, reconcile_account_index = None):
        self.epv = epv
        self.logon_account_index = logon_account_index if logon_account_index is not None else Account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX
        self.reconcile_account_index = reconcile_account_index if reconcile_account_index else Account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX

    @classmethod
    def _init_validate_class_attributes(cls, serialized: dict, section: str, configfile: str = None) -> dict:
        """_init_validate_class_attributes      Initialize and validate the Account definition (file configuration and serialized)

        Arguments:
            serialized {dict}           Definition from configuration file or serialization
            section {str}               verified section name

        Keyword Arguments:
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Returns:
            new_serialized {dict}                    Account defintion
        """
        if not configfile:
            configfile = "serialized"

        new_serialized = {}

        for k in serialized.keys():
            keyname = k.lower()

            # Special validation: integer, boolean
            if keyname in ["logon_account_index", "reconcile_account_index"]:
                new_serialized[keyname] = validate_integer(configfile, f"{section}/{keyname}", serialized[k])
            elif keyname in Account._SERIALIZED_FIELDS:
                # String definition (future use)
                new_serialized[keyname] = serialized[k]
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{section}/{k}' in {configfile}")

        # Default values if not set
        new_serialized.setdefault("logon_account_index", Account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX)
        new_serialized.setdefault("reconcile_account_index", Account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX)

        # Validation
        for keyname in ["logon_account_index", "reconcile_account_index"]:
            if new_serialized[keyname] not in [1, 2, 3]:
                raise AiobastionConfigurationException(f"Invalid value for attribute '{section}/{keyname}' in {configfile}  (expected 1 to 3): {new_serialized[keyname]!r}")


        return new_serialized


    def to_json(self):
        serialized = {}

        for attr_name in Account._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

    async def _handle_acc_list(self, api_call, account, *args, **kwargs):
        """
        Internal function to handle a list of account for a specific API call

        :param api_call: A function that perform an API call
        :param account: PrivilegedAccount, list of PrivilegedAccount, account_id or list of account_id
        :param args: Args to be passed to the function
        :param kwargs: Named args to be passed to the function
        :return: The return of the api call
        """
        if isinstance(account, list):
            tasks = []
            for a in account:
                if not isinstance(a, PrivilegedAccount) and not re.match('[0-9]*_[0-9*]', a):
                    raise AiobastionException("You must call the function with PrivilegedAccount or list of Privileged "
                                              "Accounts")

                tasks.append(api_call(a, *args, **kwargs))

            return await asyncio.gather(*tasks, return_exceptions=True)
        elif isinstance(account, PrivilegedAccount) or re.match('[0-9]*_[0-9*]', account):
            return await api_call(account, *args, **kwargs)
        else:
            raise AiobastionException("You must call the function with PrivilegedAccount or list of Privileged Accounts"
                                      "(or valid account_id for some functions)")

    async def _handle_acc_id_list(self, method, url, accounts, data=None):
        """
        Utility function for handling a list of accounts id in parameter of url::

           res = aFunction(something, goes, in)
           print(res.avalue)

        :param method: http valid method
        :param url: lambda function that return the url with an account_id parameter
        :param accounts: list of address id
        :param data: if relevant, a dict that contains data

        :return: the result of the subsequent calls
        :raises Aiobastion: if the function was not called with PrivilegedAccount(s)
        """

        async def _api_call(acc_id):
            return await self.epv.handle_request(method, url(acc_id), data=data)

        return await self._handle_acc_list(_api_call, accounts)

    async def add_account_to_safe(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]) -> str:
        """ **This function support list of PrivilegedAccount as argument**

        This function creates the PrivilegedAccount (or the list of PrivilegedAccount) in the account’s safe
        (the safe attribute of the account). If the account(s) already exists, then raises a CyberarkAPIException

        :param account: PrivilegedAccount or list ofPrivilegedAccount
        :return: account_id or list(account_id | exceptions)
        :raises CyberarkAPIException:  If there is something wrong
        """

        async def _api_call(acc):
            return await self.epv.handle_request("post", 'API/Accounts', data=acc.to_json(),
                                                 filter_func=lambda r: r["id"])

        return await self._handle_acc_list(_api_call, account)

    async def get_account(self, account_id) -> Union[PrivilegedAccount, List[PrivilegedAccount]]:
        """ **This function support list of PrivilegedAccount as argument**

        This function returns a Privileged account object for a given account_id (or list of account_id)

        :param account_id: account_id or list(account_id)
        :return: PrivilegedAccount or list(PrivilegedAccount | exceptions)
        :raises CyberarkException: 404 if the account doesn't exist.
        """
        acc = await self._handle_acc_id_list(
            "get",
            lambda a: f"API/Accounts/{a}",
            account_id
        )

        if isinstance(acc, dict):
            return PrivilegedAccount(**acc)
        else:
            return [PrivilegedAccount(**a) for a in acc]

    async def get_privileged_account_id(self, account: PrivilegedAccount):
        """
        This function returns an account_id for a given PrivilegedAccount by searching it with username,
        address and safe (mostly used for internal needs)

        :param account: PrivilegedAccount
        :return: account_id
        :raises CyberarkException: if no account was found or if multiple accounts found
        """

        if account.id == "":
            acc = await self.search_account_by(username=account.userName, safe=account.safeName,
                                               keywords=account.address)
            if len(acc) != 1:
                raise CyberarkException(f"Multiple account ID were found with {account.userName} {account.safeName} "
                                        f"{account.address}")
            else:
                return acc[0].id
        else:
            return account.id

    async def get_single_account_id(self, account):
        """
        Internal function to get a single account ID

        :param account: PrivilegedAccount object (or account_id)
        :return: account_id
        """
        if type(account) is str:
            if re.match(r'\d+_\d+', account) is not None:
                return account
            else:
                raise AiobastionException("The account_id provided is not correct")
        if isinstance(account, PrivilegedAccount):
            return await self.get_privileged_account_id(account)
        else:
            raise AiobastionException("You must provide a valid PrivilegedAccount to function get_account_id")

    async def get_account_id(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Internal function to get account ID

        :param account: PrivilegedAccount object (or account_id) or list of mixed PrivilegedAccount and account_id
        :return: account_id or list of account_id
        """
        if isinstance(account, list):
            tasks = [self.get_single_account_id(a) for a in account]
            return flatten(await asyncio.gather(*tasks, return_exceptions=False))
        else:
            return await self.get_single_account_id(account)

    async def link_reconciliation_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                          reconcile_account: PrivilegedAccount):
        """
        | This function links the account (or the list of accounts) to the given reconcile account
        | ⚠️ The "reconcile" Account is supposed to have an index of 3

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reconcile_account: The reconciliation PrivilegedAccount object
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        return await self.link_account(account, reconcile_account, 3)

    async def link_logon_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                 logon_account: PrivilegedAccount):
        """
        | This function links the account (or the list of accounts) to the given logon account
        | ⚠️ The "logon" Account is supposed to have an index of 2

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param logon_account: The logon PrivilegedAccount object
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        return await self.link_account(account, logon_account, self.logon_account_index)

    async def link_reconcile_account_by_address(self, acc_username, rec_acc_username, address):
        """ This function links the account with the given username and address to the reconciliation account with
        the given rec_account_username and the given address

        :param acc_username:  username of the account to link
        :param rec_acc_username:  username of the reconciliation account
        :param address: address of both accounts
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        acc, rec_acc = await asyncio.gather(
            self.search_account_by(username=acc_username, address=address),
            self.search_account_by(username=rec_acc_username, address=address))

        if len(acc) > 1:
            raise CyberarkException(f"More than one address {acc_username} "
                                    f"with address {address} was found !")
        if len(acc) == 0:
            raise CyberarkException(f"The account {acc_username} with address {address} "
                                    "was not found !")

        if len(rec_acc) > 1:
            raise CyberarkException(f"More than one reconciliation address {rec_acc_username} "
                                    f"with address {address} was found !")
        if len(rec_acc) == 0:
            raise CyberarkException(f"The reconciliation address {rec_acc_username} "
                                    f"with address {address} was not found !")

        return await self.link_reconciliation_account(acc[0], rec_acc[0])

    async def remove_reconcile_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | This function unlinks the reconciliation account of the given account (or the list of accounts)
        | ⚠️ The "reconcile" Account is supposed to have an index of 3
        | You can change it by setting "account" section field "reconcile_account_index" in your config file


        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        return await self.unlink_account(account, self.reconcile_account_index)

    async def remove_logon_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | This function unlinks the logon account of the given account (or the list of accounts)
        | ⚠️ The "logon" Account index is default to 2 but can be set differently on the platform
        | You can change it by setting "account" section field "logon_account_index" in your config file

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        return await self.unlink_account(account, self.logon_account_index)

    async def unlink_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                             extra_password_index: int):
        """ This function unlinks the account of the given account (or the list of accounts)
        | ⚠️ Double-check the linked account index on your platform.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param extra_password_index: The index of the account that must be unlinked
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        if extra_password_index not in [1, 2, 3]:
            raise AiobastionException("ExtraPasswordIndex must be between 1 and 3")

        return await self._handle_acc_id_list(
            "delete",
            lambda a: f"API/Accounts/{a}/LinkAccount/{extra_password_index}",
            await self.get_account_id(account)
        )

    async def link_account(self, account: PrivilegedAccount, link_account: PrivilegedAccount, extra_password_index: int,
                           folder="Root") -> bool:
        """ Links the account of the given PrivilegedAccount (or the list of accounts) to the given PrivilegedAccount

        :param account: The target address
        :param link_account: The linked address (reconcile or logon address)
        :param extra_password_index: 1 for logon, 3 for reconcile
        :param folder: "Root" by default
        :return: True if success, exception otherwise
        """
        if extra_password_index not in [1, 2, 3]:
            raise AiobastionException("ExtraPasswordIndex must be between 1 and 3")
        account_id = await self.get_account_id(account)
        if self.epv.versiontuple(await self.epv.get_version()) > self.epv.versiontuple("12.1.1"):
            data = {
                "safe": link_account.safeName,
                "extraPasswordIndex": extra_password_index,
                "name": link_account.name,
                "folder": folder
            }
        else:
            data = {
                "safe": link_account.safeName,
                "ExtraPassID": extra_password_index,
                "name": link_account.name,
                "folder": folder
            }

        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/LinkAccount",
            account_id,
            data
        )

    async def change_password(self, account: Union[PrivilegedAccount, str], change_group=False):
        """
        | This function set the account (or list) for immediate change.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param change_group: change entire group, default to False
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If change failed
        """
        data = {
            "ChangeEntireGroup": change_group
        }

        return await self._handle_acc_id_list(
            "post",
            lambda acc_id: f"API/Accounts/{acc_id}/Change",
            await self.get_account_id(account),
            data
        )

    async def reconcile(self, account: Union[PrivilegedAccount, str]):
        """
        | This function set the account (or list) for immediate reconciliation.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If reconciliation failed
        """
        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/Reconcile",
            await self.get_account_id(account)
        )

    async def verify(self, account: Union[PrivilegedAccount, str]):
        """
        | This function set the account (or list) for immediate verification.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If verify failed
        """
        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/Verify",
            await self.get_account_id(account)
        )

    def is_valid_username(self, username: str) -> bool:
        """ Check if the username is a valid Vault username

        :param username: username to check
        :return: A boolean that indicates whether the username if valid or not.
        """
        special_chars = "\\/.:*?\"<>|\t\r\n\x1F"
        return not (len(username) > 128 or any(c in special_chars for c in username))

    def is_valid_safename(self, name: str) -> bool:
        """ Check if the safename is a valid Vault safe name.

        :param name: Safe name to check
        :return: A boolean that indicates whether the username if valid or not.
        """
        special_chars = "\\/.:*?\"<>|\t\r\n\x1F"
        return not (len(name) > 28 or any(c in special_chars for c in name))

    async def search_account_by_ip_addr(self, address: Union[PrivilegedAccount, str]):
        """
        This function will search an account by IP address by checking if “address” is a valid IPv4 address
        and checking if “Address” property of the account is exactly the given address.
        You can also provide an PrivilegedAccount, the function will search on its address property

        :param address: A PrivilegedAccount object or IPv4 valid address
        :return: A list of "PrivilegedAccount" objects
        """
        if type(address) is str:
            address = address
        elif isinstance(address, PrivilegedAccount):
            address = address.address
        else:
            raise TypeError("search address function returned : First argument of address is not valid")

        if not validate_ip(address):
            raise TypeError(f"The address of the object was not considered as valid IPv4 address {address}")

        return await self.search_account_by(address=address)

    async def search_account(self, expression: str):
        """
        This function search an address using free text search and return a list a Privileged Account objects

        :param expression: List of keywords to search for in accounts, separated by a space.
        :return: List of PrivilegedAccount objects

        ℹ️ See also search_account_by function
        """
        return await self.search_account_by(expression)

    async def search_account_by(self, keywords=None, username=None, address=None, safe=None,
                                platform=None, **kwargs) -> List[PrivilegedAccount]:
        """search_account_by(keywords=None, username=None, address=None, safe=None, platform=None, **kwargs) -> list
        | This function allow to search using one or more parameters and return list of address id.
        | This is the easiest way to retrieve accounts from the vault.
        | It allows you to either search on given keywords, or more precisely on an account attribute.

        For example::

            accounts = await search_account_by(username="admin", safe="Linux-SRV", my_custom_FC="Database")

        :param keywords: free search
        :param username: username search (field "userName")
        :param address: IP address search (field "address")
        :param safe: search in particular safe
        :param platform: search by platform name (no space) (field "platformId")
        :param kwargs: any searchable key = value

        :return: A list of PrivilegedAccounts

        ⚠️ **Note**: This function doesn’t populate the secret field (password), you have to make a separated call if you
        want to get it.

        """

        return [account async for account in
                self.search_account_iterator(keywords, username, address, safe, platform, **kwargs)]

    async def search_account_iterator(self, keywords=None, username=None, address=None, safe=None,
                                      platform=None, **kwargs) -> AsyncIterator[PrivilegedAccount]:
        """
        | This function allow to search using one or more parameters and return list of address id.

        :param keywords: free search
        :param username: username search (field "userName")
        :param address: IP address search (field "address")
        :param safe: search in particular safe
        :param platform: search by platform name (no space) (field "platformId")
        :param kwargs: any searchable key = value

        :return: an async generator of PrivilegedAccounts

        ℹ️ See also search_account_by
        """

        filtered_args = {k: v for k, v in locals().items() if v and k not in ["safe", "self", "keywords", "kwargs"]}
        filtered_args.update(kwargs)

        page = 1
        has_next_page = True

        while has_next_page:
            accounts = await self.search_account_paginate(page=page, safe=safe, search=keywords, **filtered_args)
            has_next_page = accounts["has_next_page"]
            page += 1
            for a in accounts["accounts"]:
                yield a

    async def search_account_paginate(self, page: int = 1, size_of_page: int = 1000, safe: str = None,
                                      search: str = None, **kwargs):
        """
        Search accounts in a paginated way

        :param search: free search
        :param page: The page number (starting at 1)
        :param size_of_page: the size of pages (max 1000)
        :param safe: the safe name, if wanted
        :param kwargs: whatever file category you want to find
        :return:
            A dictionary with keys:

            - accounts : This is a list of matched account for the given page
            - has_next_page : A boolean hat indicated if there is a next page

        ℹ️ For your convenience you can use platform=”PF-NAME” instead of platformID (and thus if you have a custom
        “platform” FC it will not be considered).
        """

        try:
            params = {"search": " ".join(kwargs.values())}
        except TypeError as err:
            raise AiobastionException(f"You can't search on a list here ({kwargs.values()}), "
                                      "provide a string instead") from err

        if search is not None:
            params["search"] += f" {search}"

        if safe is not None:
            params["filter"] = "safeName eq " + safe

        params["limit"] = size_of_page
        params["offset"] = (page - 1) * size_of_page
        search_results = await self.epv.handle_request("get", "API/Accounts", params=params,
                                                       filter_func=lambda x: x)
        account_list = search_results['value']
        # check for each address if the content of FC match the search
        filtered_account_list = filter(lambda f: _filter_account(f, kwargs), account_list)
        # for each filtered address, build the PrivilegedAccount
        filtered_acc_list = [PrivilegedAccount(**acc) for acc in filtered_account_list]

        has_next_page = "nextLink" in search_results
        return {
            "accounts": filtered_acc_list,
            "has_next_page": has_next_page
        }

    async def connect_using_PSM(self, account, connection_component, reason: str = ""):
        """ This function returns a file content (bytes) which is the equivalent RDP file of the “Connect” button

        For example::

            async with production_vault as epv:
                # find first active connexion component
                try:
                    unique_id = await epv.platform.get_target_platform_unique_id(account.platformId)
                    ccs = await epv.platform.get_target_platform_connection_components(unique_id)
                    cc = None
                    for _cc in ccs:
                        if _cc["Enabled"]:
                            cc = _cc["PSMConnectorID"]
                            break
                except CyberarkException as err:
                    # You are not Vault Admin
                    self.assertIn("PASWS041E", str(err))

                rdp_content = await epv.account.connect_using_PSM(account.id, cc)
                with open("connect_account.rdp", "w") as rdp_file:
                    rdp_file.write(rdp_content)

        :param account: PrivilegedAccount or account_id
        :param connection_component: the connection component to connect with
        :param reason: the reason that is required to request access to this account
        :return: file_content
        :raises CyberarkAPIException:  if an error occured
        """
        account_id = await self.get_account_id(account)
        url, head = self.epv.get_url(f"API/Accounts/{account_id}/PSMConnect")
        head["Accept"] = 'RDP'
        body = {"ConnectionComponent": connection_component}
        if reason: body["Reason"] = reason

        async with aiohttp.ClientSession(headers=head, cookies = self.epv.cookies) as session:
            async with session.post(url, json=body, **self.epv.request_params) as req:
                if req.status != 200:
                    content = await req.json()
                    raise CyberarkAPIException(req.status, content["ErrorCode"], content["ErrorMessage"])

                return await req.read()

    async def disable_password_management(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                          reason: str = ""):
        """ This disables the account (or list) password management

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reason: The reason of disabling password management (defaults to empty string)
        :return: The list of updated accounts, or exceptions
        :raises CyberarkException: If disabling failed.
        """
        data = [
            {"op": "replace", "path": "/secretManagement/automaticManagementEnabled", "value": False},
            {"op": "add", "path": "/secretManagement/manualManagementReason", "value": reason}
        ]

        _results = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )
        # Single item
        if isinstance(_results, dict):
            return PrivilegedAccount(**_results)
        # list
        else:
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in _results]

    async def resume_password_management(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """ This resume the account (or list) password management

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The list of updated accounts, or exceptions
        :raises CyberarkException: If resuming failed.
        """

        data = [
            {"op": "replace", "path": "/secretManagement/automaticManagementEnabled", "value": True},
        ]
        _results = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )

        # Single item
        if isinstance(_results, dict):
            return PrivilegedAccount(**_results)
        # list
        else:
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in _results]
        # return await self.epv.handle_request("patch", f"API/Accounts/{account_id}", data=data)

    async def update_using_list(self, account, data) -> Union[PrivilegedAccount, List[PrivilegedAccount]]:
        """ **This function support list of PrivilegedAccount as argument**

        | This function updates an account (or list) with the data list of changes. For more infos, check CyberArk doc.
        | Valid operations are : Replace, Remove or Add

        For example::

            # insert here logon to vault and retrieve an account
            data = [
                {"path": "/name", "op": "replace", "value": new_name},
                {"path": "/address", "op": "replace", "value": new_address},
                {"path": "/platformId", "op": "replace", "value": new_platformId},
            ]
            is_updated = await epv.account.update_using_list(account, data)


        :param account: address, list of accounts, account_id, list of accounts id
        :param data: The list of FC to change.

        :return: The updated PrivilegedAccount or the list of updated PrivilegedAccount
        """
        updated_accounts = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )
        if isinstance(updated_accounts, dict):
            return PrivilegedAccount(**updated_accounts)
        else:
            # Will return exception if met
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in updated_accounts]
            # return [PrivilegedAccount(**u) for u in updated_accounts]

    def detect_fc_path(self, fc: str):
        """
        Detect the path of the File Category

        :param fc: the name of the File Category
        :return: The string representing the Path to the FC
        """
        if fc in BASE_FILECATEGORY:
            return "/"
        elif fc in SECRET_MANAGEMENT_FILECATEGORY:
            return "/secretmanagement/"
        else:
            return "/platformaccountproperties/"

    async def update_single_fc(self,  account, file_category, new_value, operation="replace"):
        """
        Update / Delete / Create a File Category for an account or a list of accounts
        The path of the file_category is (hopefully) automatically detected

        :param account: address, list of accounts, account_id, list of accounts id
        :param file_category: the File Category to update
        :param new_value: The new value of the FC
        :param operation: Replace, Remove or Add
        :return: The updated PrivilegedAccount or the list of updated PrivilegedAccount
        :raises AiobastionException: if the FC was not found in the Vault
        :raises CyberarkAPIException: if another error occured
        """
        # if we "add" and FC exists it will replace it
        data = [{"path": f"{self.detect_fc_path(file_category)}{file_category}", "op": operation, "value": new_value}]
        try:
            return await self.update_using_list(account, data)
        except CyberarkAPIException as err:
            if err.err_code == "PASWS164E" and operation == "replace":
                # Try to add FC instead of replacing it
                return await self.update_single_fc(account, file_category, new_value, "add")
            if err.http_status == 400:
                raise AiobastionException("The FC was not found in the Vault (it is case sensitive)") from err
            else:
                raise

    async def update_file_category(self, account, file_category, new_value):
        """
        Update the file category (or list of FC) with the new value (or list of new values)
        If the FC does not exist, it will create it

        :param account: address, list of accounts, account_id, list of accounts id
        :param file_category: a file category or a list of file category
        :param new_value: the new value of the list of new values

        """
        data = []
        if isinstance(file_category, list):
            try:
                assert isinstance(new_value, list)
            except AssertionError:
                raise AiobastionException("If file_category is a list, then new value must be a list as well")
            try:
                assert len(file_category) == len(new_value)
            except AssertionError:
                raise AiobastionException("You must provide the same list size for file_category and values")
            for f,n in zip(file_category, new_value):
                # we trust user and don't check if FC is defined at platform level
                data.append({"path": f"{self.detect_fc_path(f)}{f}", "op": "add", "value": n})
        else:
            data.append({"path": f"{self.detect_fc_path(file_category)}{file_category}", "op": "add", "value": new_value})

        return await self.update_using_list(account, data)


    async def restore_last_cpm_version(self, account: PrivilegedAccount, cpm):
        """
        Find in the history of passwords the last password set by the CPM and updates the password accordingly
        in the Vault

        :param account: a PrivilegedAccount object
        :param cpm: the name of the CPM who set the password
        :return: True if success
        :raises AiobastionException: if no CPM version was found
        """
        versions = await self.get_secret_versions(account)
        cpm_versions = [v["versionID"] for v in versions if v["modifiedBy"] == cpm]
        if len(cpm_versions) > 0:
            good_ver = max(cpm_versions)
            password_to_set = await self.get_secret_version(account, good_ver)
            return await self.set_password(account,password_to_set)
        else:
            raise AiobastionException("There is no CPM version for this account")

    async def restore_last_cpm_version_by_cpm(self, account: PrivilegedAccount, cpm):
        """
        Find in the history of passwords the last password set by the CPM and schedule a password change with this value

        :param account: a PrivilegedAccount object
        :param cpm: the name of the CPM who set the password
        :return: True if success
        :raises AiobastionException: if there is no CPM version for this account
        """
        versions = await self.get_secret_versions(account)
        cpm_versions = [v["versionID"] for v in versions if v["modifiedBy"] == cpm]
        if len(cpm_versions) > 0:
            good_ver = max(cpm_versions)
            password_to_set = await self.get_secret_version(account, good_ver)
            return await self.set_next_password(account, password_to_set)
        else:
            raise AiobastionException("There is no CPM version for this account")

    async def get_secret_version(self, account: PrivilegedAccount, version: int, reason: str = None):
        """
        Get the version of a password

        :param account: a PrivilegedAccount object
        :param version: the version ID (that you can find with get_secret_versions). The higher is the most recent.
        :param reason: The reason that is required to retrieve the password
        :return: the secret
        :raises CyberarkException: if the version was not found
        """
        if version < 1:
            raise AiobastionException("The version must be a non-zero natural integer")

        data = {"Version": version}
        if reason: data["Reason"] = reason
        account_id = await self.get_account_id(account)

        url = f"API/Accounts/{account_id}/Password/Retrieve"

        return await self.epv.handle_request("post", url, data=data)

    async def get_password(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]], reason: str = None):
        """
        | Retrieve the password of an address
        | ✅ Use get_secret instead if you want to retrieve password or ssh_key

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reason: The reason that is required to retrieve the password
        :return: Account password value  (or list of passwords)
        :raises CyberarkException: If retrieve failed
        """
        data = {}
        if reason: data = {"Reason": reason}
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Password/Retrieve",
            await self.get_account_id(account),
            data = data
        )


    # Test me
    async def get_ssh_key(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Retrieve the SSH Key of an account

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: SSH key value, or a list of ssh key values
        """

        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Secret/Retrieve",
            await self.get_account_id(account)
        )

    async def get_secret_versions(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]], reason: str = None):
        """
        Retrieve the secret versions

        :param account: Privileged Account or address id
        :param reason: The reason that is required to retrieve the password
        :return: Account password value
        """
        data = {}
        if reason: data = {"Reason": reason}
        versions = await self._handle_acc_id_list(
            "get",
            lambda account_id: f"API/Accounts/{account_id}/Secret/Versions/",
            await self.get_account_id(account),
            data = data
        )

        if isinstance(versions, list):
            return [v["Versions"] for v in versions]
        elif isinstance(versions, dict):
            return versions["Versions"]
        else:
            raise AiobastionException(versions)

    # Test
    async def get_secret(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Get the secret of an account, detecting if the secret type is password or key

        :param account: A PrivilegedAccount object, or a list of PrivilegedAccount objects
        :return: The password, key or list of passwords / keys.
        """
        if isinstance(account, list):
            tasks = []
            for a in account:
                if a.secretType == "key":
                    tasks.append(self.get_ssh_key(a))
                else:
                    tasks.append(self.get_password(a))
            return await asyncio.gather(*tasks)
        else:
            if account.secretType == "key":
                return await self.get_ssh_key(account)
            else:
                return await self.get_password(account)

    async def set_password(self, account, password):
        """
        Set the password for the given address **in the Vault**

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param password: new password to set
        :return: True if success
        :raises CyberarkException: If set password failed (your platform enforce complexity, or you don’t have rights)
        """
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Password/Update",
            await self.get_account_id(account),
            {"NewCredentials": password}
        )

    async def set_next_password(self, account, password):
        """
        Set the next password for the given address to be set by the CPM

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param password: new password to set
        :return: True if change was successfully planned.
        """
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/SetNextPassword",
            await self.get_account_id(account),
            {"ChangeImmediately": True, "NewCredentials": password}
        )

    async def delete(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """ **This function support list of PrivilegedAccount as argument**

        | This deletes the account (or list).
        | ⚠️ If this is an SSH Key, this function will delete it on the Vault but not on systems!

        :param account: PrivilegedAccount or list(PrivilegedAccount) to delete
        :return: True if succeeded
        :raises CyberarkException: If delete failed
        """
        # account_id = await self.get_account_id(address),
        async def api_call(account_id):
            try:
                return await self.epv.handle_request("delete", f"API/Accounts/{account_id}")
            except CyberarkAPIException:
                return await self.epv.handle_request("delete", f"WebServices/PIMServices.svc/Accounts/{account_id}")

        return await self._handle_acc_list(
            api_call,
            await self.get_account_id(account)
        )

    async def get_cpm_status(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | Get the CPM status of an account or a list of accounts.
        | ✅ You can also use the cpm_status() method of the object PrivilegedAccount

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The secretManagement dictionary of the account.
        """
        if isinstance(account, list):
            return [a.secretManagement for a in account]
        else:
            return account.secretManagement

    async def activity(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        Get account(s) activity

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The activity dictionary as-is it is returned by CyberArk
        :raises CyberarkException: If call failed
        """
        activities = await self._handle_acc_id_list(
            "get",
            lambda account_id: f"WebServices/PIMServices.svc/Accounts/{account_id}/Activities/",
            await self.get_account_id(account)
        )

        if isinstance(activities, list):
            return [a["GetAccountActivitiesSlashResult"] for a in activities]
        elif isinstance(activities, dict):
            return activities["GetAccountActivitiesSlashResult"]
        else:
            return None

    async def last_cpm_error_message(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        Get the last CPM Error message

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The last CPM error status, or None
        :raises CyberarkException: If link failed
        """
        activities = await self.activity(account)

        def single_cpm_error(activity):
            """
            Get the very last error for an activity dict

            :param activity: The CyberArk activity dict
            :return: The last CPM error if any
            """
            for a in activity:
                if "CPM" in a["Activity"]:
                    if "Failure" in a["Reason"]:
                        reason = a["Reason"].split("Error:")
                        return reason[1]

        # List of list
        if any(isinstance(el, list) for el in activities):
            return [single_cpm_error(_activity) for _activity in activities]
        else:
            return single_cpm_error(activities)

    async def add_member_to_group(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                  group_name: str = "") -> str:
        """ **This function support list of PrivilegedAccount as argument**
        Add an address to a group

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list

        :param group_name: name of the group (or try the address username if empty)
        :return: AccountID
        """
        groups = await self.epv.accountgroup.list_by_safe(account.safeName)
        group_id = 0
        if group_name == "":
            for group in groups:
                if account.userName.lower() in group.name.lower():
                    group_id = group.id
        else:
            for group in groups:
                if group_name.lower() == group.name.lower():
                    group_id = group.id
        if group_id == 0:
            raise AiobastionException("Group name was incorrect or not found")

        async def _api_call(acc):
            url = f"API/AccountGroups/{group_id}/Members"
            data = {"AccountId": acc.id}
            return await self.epv.handle_request("post", url, data=data)

        return await self._handle_acc_list(
            _api_call,
            account
        )

    async def get_account_group(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | Returns the GroupID of a given PrivilegedAccount
        | To get the group name, and more, check the Account Group section of this documentation.

        :param account: PrivilegedAccount, list of Privileged Accounts
        :type account: PrivilegedAccount, list
        :return: GroupID (which is not the group name)
        """

        async def _api_call(acc):
            for group in await self.epv.accountgroup.list_by_safe(acc.safeName):
                groupid = group.id
                for member in await self.epv.accountgroup.members(groupid):
                    if member.id == acc.id:
                        return groupid
            return None

        return await self._handle_acc_list(_api_call, account)

    async def del_account_group_membership(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """ Find and delete the account_group membership of a PrivilegedAccount (or list)

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: False if no group was remove, True is a group was deleted
        :raises CyberarkAPIException: if a group was found but deletion didn't work
        """

        async def _del_accountgroup(acc):
            groupid = await self.get_account_group(acc)
            if groupid is None:
                return False
            else:
                try:
                    await self.epv.accountgroup.delete_member(acc, groupid)
                except Exception as err:
                    raise CyberarkException("Unable to remove address group " + str(err))
                return True

        return await self._handle_acc_list(_del_accountgroup, account)

    async def update_platform(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], new_platform: str):
        """ This function updates the account’s (or list) platform

        :param account: PrivilegedAccount, list of Privileged Accounts
        :param new_platform: The new plaform ID (e.g. Unix-SSH)
        :return: True if succeeded
        """

        data = [{"path": "/platformID", "op": "replace", "value": new_platform}]
        return await self.epv.account.update_using_list(account, data)

    async def move(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], new_safe: str):
        """ Delete the account (or list) and recreate it (or them) in with the same parameters and password in the new
        safe.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param new_safe: New safe to move the account(s) into
        :return: Boolean that indicates if the operation was successful
        """
        async def _move(acc):
            self.epv.logger.debug(f"Now trying to move {acc} to {new_safe}")
            old_id = acc.id
            acc.safeName = new_safe
            try:
                acc.secret = await self.get_password(acc)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to recover {acc.name} password : {str(err)}")
            try:
                new_account_id = await self.add_account_to_safe(acc)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to create {acc.name} new address : {str(err)}")
            try:
                await self.delete(old_id)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to delete {acc.name} old address : {str(err)}")
            return new_account_id

        return await self._handle_acc_list(_move, account)

    # AIM get secret function
    async def get_secret_aim(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], reason: str = None):
        """ **This function support list of PrivilegedAccount as argument**

        | This function update the secret attribute of the PrivilegedAccount with the password
          returned by the **AIM Web service**. If the account is not found, the secret is set to None.

        :param account: A PrivilegedAccount object, or a list of PrivilegedAccount objects
        :param reason: The reason for retrieving the password. This reason will be audited in the Credential
            Provider audit log. (optional)
        :type account: PrivilegedAccount, list
        :return: PrivilegedAccount Object updated, if the password is not found the secret will be None
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :raise AiobastionException: AIM configuration setup error
        """
        if self.epv.AIM is None:
            raise AiobastionException(
                    "Missing AIM information to perform AIM authentication, see documentation")

        if isinstance(account, list):
            tasks = []
            for acc in account:
                if not acc.secretType or (acc.secretType and acc.secretType == "password"):
                    tasks.append(self.get_secret_aim(acc, reason))
            return await asyncio.gather(*tasks)

        # Deal with a single account
        if not isinstance(account, PrivilegedAccount):
            raise AiobastionException("You must provide a valid PrivilegedAccount.")

        params={"object": account.name }

        if reason:
            params["reason"] = reason
        if account.safeName:
            params["safe"] = account.safeName

        try:
            account.secret = await self.epv.AIM.get_secret(**params)

        except CyberarkAIMnotFound:
            account.secret = None

        return account


    async def get_password_aim(self, **kwargs):
        """
        | Retrieve secret password from the Central Credential Provider (**AIM**) GetPassword
          Web Service information.

        | ℹ️ The following parameters are optional searchable keys. Refer to
            `CyberArk Central Credential Provider - REST web service`.

        :param username: User account name
        :param safe: Safe where the account is stored.
        :param object: Name of the account to retrieve (unique for a specific safe).
        :param folder: Name of the folder property
        :param address: Address account property
        :param database: Database account property
        :param policyid: Policy account property
        :param reason: The reason for retrieving the password. This reason will be audited in the Credential
            Provider audit log.
        :param query: Defines a free query using account properties, including Safe, folder, and object.
            When this method is specified, all other search criteria
            (Safe/Folder/ Object/UserName/Address/PolicyID/Database) are ignored and only the
            account properties that are specified in the query are passed to the Central
            Credential Provider in the password request.
        :param queryformat: Defines the query format, which can optionally use regular expressions.
            Possible values are: Exact or Regexp
        :param failrequestonpasswordchange: Boolean, Whether or not an error will be returned if
            this web service is called when a password change process is underway.
        :return:  namedtuple of (secret, detail)

        |            secret = password
        |            detail = dictionary from the Central Credential Provider (AIM) GetPassword Web
                               Service.

        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :raise AiobastionException: AIM configuration setup error
        """
        if self.epv.AIM is None:
            raise AiobastionException(
                    "Missing AIM information to perform AIM authentication, see documentation")

        return await self.epv.AIM.get_secret_detail(**kwargs)
=======
# -*- coding: utf-8 -*-
import asyncio
import re
from typing import List, Union, AsyncIterator

import aiohttp

from .config import validate_ip, flatten, validate_integer
from .exceptions import (
    CyberarkAPIException, CyberarkException, AiobastionException, CyberarkAIMnotFound, AiobastionConfigurationException
)

BASE_FILECATEGORY = ("platformId", "userName", "address", "name")
SECRET_MANAGEMENT_FILECATEGORY = ("automaticManagementEnabled", "manualManagementReason", "lastModifiedTime",
                                  "lastReconciledTime", "lastVerifiedTime", "status")


class PrivilegedAccount:
    """Base class to be used with accounts fonctions"""

    def __init__(self, name: str, platformId: str, safeName: str,
                 platformAccountProperties: dict = None, secret: str = "", secretType: str = None,
                 secretManagement: dict = None,
                 remoteMachinesAccess: dict = None,
                 id: str = "", address: str = "", userName: str = "",
                 **other):
        self.secret = secret
        if remoteMachinesAccess is not None:
            if not all([k in ["remoteMachines", "accessRestrictedToRemoteMachines"]
                        for k in remoteMachinesAccess.keys()]):
                raise AiobastionException("remoteMachinesAccess is not a valid dictionary")
        if secretManagement is None:
            secretManagement = {"automaticManagementEnabled": True, "manualManagementReason": ""}
        self.remoteMachinesAccess = remoteMachinesAccess
        self.secretManagement = secretManagement
        self.secretType = secretType
        if secretType not in [None, "password", "key"]:
            raise AiobastionException("secretType is not valid")
        if platformAccountProperties is None:
            platformAccountProperties = {}
        self.platformAccountProperties = platformAccountProperties
        self.safeName = safeName
        self.platformId = platformId
        self.userName = userName
        self.address = address
        self.name = name
        self.id = id
        for k, v in other.items():
            setattr(self, k, v)

    def get_name(self):
        """ Get a default name of a Privileged Account

        :return: address-username of the PrivilegedAccount
        """
        return f"{self.address}-{self.userName}"

    def to_json(self):
        """
        Convert the PrivilegedAccount object to a python dict object

        :return: A JSON ready to use object
        """
        json_object = {"id": self.id, "name": self.name, "address": self.address, "userName": self.userName,
                       "platformId": self.platformId, "safeName": self.safeName, "secret": self.secret,
                       "platformAccountProperties": self.platformAccountProperties,
                       "secretManagement": self.secretManagement}
        if self.remoteMachinesAccess is not None:
            json_object["remoteMachinesAccess"] = self.remoteMachinesAccess
        if self.secretType is not None:
            json_object["secretType"] = self.secretType

        return json_object

    def to_dict(self):
        """
        Convert the PrivilegedAccount object to a python dict object

        :return: a dict
        """
        return self.to_json()

    def __str__(self):
        strrepr = self.to_json()
        return str(strrepr)

    # Mapping Protocol
    def __iter__(self):
        for key, value in self.to_dict():
            yield key, value

    def keys(self):
        return list(self.to_dict().keys())

    def items(self):
        return list(self.to_dict().items())

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __eq__(self, other):
        # Check by ID is the best way
        if self.id != "" and other.id != "":
            return self.id == other.id
        # Else we check by name and safeName (Cyberark prevent different objects to have the same name in the same safe)
        else:
            return (self.safeName == other.safeName) and (self.name == other.name)

        # return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        # Check by ID is the best way
        if self.id != "" and other.id != "":
            return self.id != other.id
        # Else we check by name and safeName (Cyberark prevents object to have the same name in the same safe)
        else:
            return (self.safeName != other.safeName) or (self.name != other.name)

    # End of mapping Protocol


    def __repr__(self):
        # For Debugging, short account identification
        s = f"<{self.__class__.__name__} {hex(id(self))}:"

        for attr in ["id", "name", "safeName"]:
            v = getattr(self, attr, None)
            if v:
                s += f" {attr}={v}"

        s += ">"

        return s

    def cpm_status(self):
        """
        Get the CPM Status of an account

        :return: "success" "failure "Deactivated" or "No status (yet)"
        """
        if "status" in self.secretManagement:
            # 'success' or 'failure'
            return self.secretManagement["status"]
        elif "automaticManagementEnabled" in self.secretManagement and \
                not self.secretManagement["automaticManagementEnabled"]:
            return "Deactivated"
        else:
            return "No status (yet)"

    def last_modified(self, days=True):
        """
        Get the last modified time of an PrivilegedAccount secret

        :param days: Indicates if the return must be a timestamp or a number of days (default)
        :return: The timestamp or the number of days since last change
        """
        import time
        if "lastModifiedTime" in self.secretManagement:
            ts = self.secretManagement["lastModifiedTime"]
            if days:
                return int((int(time.time()) - ts) / 86400)
            else:
                return ts


def _filter_account(account: dict, filters: dict):
    """
    This function helps to ensure that search accounts match with requested accounts

    :param account: one json CyberArk repr of a privileged address
    :param filters: one dict like username: admin
    :return: check if content of privileged FC is exactly the content of the filter
    """
    for k, v in filters.items():
        if k.lower() == "username":
            if "userName" not in account:
                return False
            if account['userName'].upper() != v.upper():
                return False
        elif k.lower() == "address":
            if account['address'].upper() != v.upper():
                return False
        elif k.lower() in ("platform", "platformid"):
            if account['platformId'].upper() != v.upper():
                return False
        elif k.lower() == "name":
            if account['name'].upper() != v.upper():
                return False
        elif k not in account['platformAccountProperties']:
            return False
        elif account['platformAccountProperties'][k] != v:
            return False
    return True


class Account:
    """
    Utility class to handle account manipulation
    """
    _ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX = 2
    _ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX = 3

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = ["logon_account_index",
                          "reconcile_account_index"]


    def __init__(self, epv, logon_account_index = None, reconcile_account_index = None):
        self.epv = epv
        self.logon_account_index = logon_account_index if logon_account_index is not None else Account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX
        self.reconcile_account_index = reconcile_account_index if reconcile_account_index else Account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX

    @classmethod
    def _init_validate_class_attributes(cls, serialized: dict, section: str, configfile: str = None) -> dict:
        """_init_validate_class_attributes      Initialize and validate the Account definition (file configuration and serialized)

        Arguments:
            serialized {dict}           Definition from configuration file or serialization
            section {str}               verified section name

        Keyword Arguments:
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Returns:
            new_serialized {dict}                    Account defintion
        """
        if not configfile:
            configfile = "serialized"

        new_serialized = {}

        for k in serialized.keys():
            keyname = k.lower()

            # Special validation: integer, boolean
            if keyname in ["logon_account_index", "reconcile_account_index"]:
                new_serialized[keyname] = validate_integer(configfile, f"{section}/{keyname}", serialized[k])
            elif keyname in Account._SERIALIZED_FIELDS:
                # String definition (future use)
                new_serialized[keyname] = serialized[k]
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{section}/{k}' in {configfile}")

        # Default values if not set
        new_serialized.setdefault("logon_account_index", Account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX)
        new_serialized.setdefault("reconcile_account_index", Account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX)

        # Validation
        for keyname in ["logon_account_index", "reconcile_account_index"]:
            if new_serialized[keyname] not in [1, 2, 3]:
                raise AiobastionConfigurationException(f"Invalid value for attribute '{section}/{keyname}' in {configfile}  (expected 1 to 3): {new_serialized[keyname]!r}")


        return new_serialized


    def to_json(self):
        serialized = {}

        for attr_name in Account._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

    async def _handle_acc_list(self, api_call, account, *args, **kwargs):
        """
        Internal function to handle a list of account for a specific API call

        :param api_call: A function that perform an API call
        :param account: PrivilegedAccount, list of PrivilegedAccount, account_id or list of account_id
        :param args: Args to be passed to the function
        :param kwargs: Named args to be passed to the function
        :return: The return of the api call
        """
        if isinstance(account, list):
            tasks = []
            for a in account:
                if not isinstance(a, PrivilegedAccount) and not re.match('[0-9]*_[0-9*]', a):
                    raise AiobastionException("You must call the function with PrivilegedAccount or list of Privileged "
                                              "Accounts")

                tasks.append(api_call(a, *args, **kwargs))

            return await asyncio.gather(*tasks, return_exceptions=True)
        elif isinstance(account, PrivilegedAccount) or re.match('[0-9]*_[0-9*]', account):
            return await api_call(account, *args, **kwargs)
        else:
            raise AiobastionException("You must call the function with PrivilegedAccount or list of Privileged Accounts"
                                      "(or valid account_id for some functions)")

    async def _handle_acc_id_list(self, method, url, accounts, data=None):
        """
        Utility function for handling a list of accounts id in parameter of url::

           res = aFunction(something, goes, in)
           print(res.avalue)

        :param method: http valid method
        :param url: lambda function that return the url with an account_id parameter
        :param accounts: list of address id
        :param data: if relevant, a dict that contains data

        :return: the result of the subsequent calls
        :raises Aiobastion: if the function was not called with PrivilegedAccount(s)
        """

        async def _api_call(acc_id):
            return await self.epv.handle_request(method, url(acc_id), data=data)

        return await self._handle_acc_list(_api_call, accounts)

    async def add_account_to_safe(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]) -> str:
        """ **This function support list of PrivilegedAccount as argument**

        This function creates the PrivilegedAccount (or the list of PrivilegedAccount) in the account’s safe
        (the safe attribute of the account). If the account(s) already exists, then raises a CyberarkAPIException

        :param account: PrivilegedAccount or list ofPrivilegedAccount
        :return: account_id or list(account_id | exceptions)
        :raises CyberarkAPIException:  If there is something wrong
        """

        async def _api_call(acc):
            return await self.epv.handle_request("post", 'API/Accounts', data=acc.to_json(),
                                                 filter_func=lambda r: r["id"])

        return await self._handle_acc_list(_api_call, account)

    async def get_account(self, account_id) -> Union[PrivilegedAccount, List[PrivilegedAccount]]:
        """ **This function support list of PrivilegedAccount as argument**

        This function returns a Privileged account object for a given account_id (or list of account_id)

        :param account_id: account_id or list(account_id)
        :return: PrivilegedAccount or list(PrivilegedAccount | exceptions)
        :raises CyberarkException: 404 if the account doesn't exist.
        """
        acc = await self._handle_acc_id_list(
            "get",
            lambda a: f"API/Accounts/{a}",
            account_id
        )

        if isinstance(acc, dict):
            return PrivilegedAccount(**acc)
        else:
            return [PrivilegedAccount(**a) for a in acc]

    async def get_privileged_account_id(self, account: PrivilegedAccount):
        """
        This function returns an account_id for a given PrivilegedAccount by searching it with username,
        address and safe (mostly used for internal needs)

        :param account: PrivilegedAccount
        :return: account_id
        :raises CyberarkException: if no account was found or if multiple accounts found
        """

        if account.id == "":
            acc = await self.search_account_by(username=account.userName, safe=account.safeName,
                                               keywords=account.address)
            if len(acc) != 1:
                raise CyberarkException(f"Multiple account ID were found with {account.userName} {account.safeName} "
                                        f"{account.address}")
            else:
                return acc[0].id
        else:
            return account.id

    async def get_single_account_id(self, account):
        """
        Internal function to get a single account ID

        :param account: PrivilegedAccount object (or account_id)
        :return: account_id
        """
        if type(account) is str:
            if re.match(r'\d+_\d+', account) is not None:
                return account
            else:
                raise AiobastionException("The account_id provided is not correct")
        if isinstance(account, PrivilegedAccount):
            return await self.get_privileged_account_id(account)
        else:
            raise AiobastionException("You must provide a valid PrivilegedAccount to function get_account_id")

    async def get_account_id(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Internal function to get account ID

        :param account: PrivilegedAccount object (or account_id) or list of mixed PrivilegedAccount and account_id
        :return: account_id or list of account_id
        """
        if isinstance(account, list):
            tasks = [self.get_single_account_id(a) for a in account]
            return flatten(await asyncio.gather(*tasks, return_exceptions=False))
        else:
            return await self.get_single_account_id(account)

    async def link_reconciliation_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                          reconcile_account: PrivilegedAccount):
        """
        | This function links the account (or the list of accounts) to the given reconcile account
        | ⚠️ The "reconcile" Account is supposed to have an index of 3

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reconcile_account: The reconciliation PrivilegedAccount object
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        return await self.link_account(account, reconcile_account, 3)

    async def link_logon_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                 logon_account: PrivilegedAccount):
        """
        | This function links the account (or the list of accounts) to the given logon account
        | ⚠️ The "logon" Account is supposed to have an index of 2

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param logon_account: The logon PrivilegedAccount object
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        return await self.link_account(account, logon_account, self.logon_account_index)

    async def link_reconcile_account_by_address(self, acc_username, rec_acc_username, address):
        """ This function links the account with the given username and address to the reconciliation account with
        the given rec_account_username and the given address

        :param acc_username:  username of the account to link
        :param rec_acc_username:  username of the reconciliation account
        :param address: address of both accounts
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed
        """
        acc, rec_acc = await asyncio.gather(
            self.search_account_by(username=acc_username, address=address),
            self.search_account_by(username=rec_acc_username, address=address))

        if len(acc) > 1:
            raise CyberarkException(f"More than one address {acc_username} "
                                    f"with address {address} was found !")
        if len(acc) == 0:
            raise CyberarkException(f"The account {acc_username} with address {address} "
                                    "was not found !")

        if len(rec_acc) > 1:
            raise CyberarkException(f"More than one reconciliation address {rec_acc_username} "
                                    f"with address {address} was found !")
        if len(rec_acc) == 0:
            raise CyberarkException(f"The reconciliation address {rec_acc_username} "
                                    f"with address {address} was not found !")

        return await self.link_reconciliation_account(acc[0], rec_acc[0])

    async def remove_reconcile_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | This function unlinks the reconciliation account of the given account (or the list of accounts)
        | ⚠️ The "reconcile" Account is supposed to have an index of 3
        | You can change it by setting "account" section field "reconcile_account_index" in your config file


        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        return await self.unlink_account(account, self.reconcile_account_index)

    async def remove_logon_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | This function unlinks the logon account of the given account (or the list of accounts)
        | ⚠️ The "logon" Account index is default to 2 but can be set differently on the platform
        | You can change it by setting "account" section field "logon_account_index" in your config file

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        return await self.unlink_account(account, self.logon_account_index)

    async def unlink_account(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                             extra_password_index: int):
        """ This function unlinks the account of the given account (or the list of accounts)
        | ⚠️ Double-check the linked account index on your platform.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param extra_password_index: The index of the account that must be unlinked
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If link failed:
        """
        if extra_password_index not in [1, 2, 3]:
            raise AiobastionException("ExtraPasswordIndex must be between 1 and 3")

        return await self._handle_acc_id_list(
            "delete",
            lambda a: f"API/Accounts/{a}/LinkAccount/{extra_password_index}",
            await self.get_account_id(account)
        )

    async def link_account(self, account: PrivilegedAccount, link_account: PrivilegedAccount, extra_password_index: int,
                           folder="Root") -> bool:
        """ Links the account of the given PrivilegedAccount (or the list of accounts) to the given PrivilegedAccount

        :param account: The target address
        :param link_account: The linked address (reconcile or logon address)
        :param extra_password_index: 1 for logon, 3 for reconcile
        :param folder: "Root" by default
        :return: True if success, exception otherwise
        """
        if extra_password_index not in [1, 2, 3]:
            raise AiobastionException("ExtraPasswordIndex must be between 1 and 3")
        account_id = await self.get_account_id(account)
        if self.epv.versiontuple(await self.epv.get_version()) > self.epv.versiontuple("12.1.1"):
            data = {
                "safe": link_account.safeName,
                "extraPasswordIndex": extra_password_index,
                "name": link_account.name,
                "folder": folder
            }
        else:
            data = {
                "safe": link_account.safeName,
                "ExtraPassID": extra_password_index,
                "name": link_account.name,
                "folder": folder
            }

        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/LinkAccount",
            account_id,
            data
        )

    async def change_password(self, account: Union[PrivilegedAccount, str], change_group=False):
        """
        | This function set the account (or list) for immediate change.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param change_group: change entire group, default to False
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If change failed
        """
        data = {
            "ChangeEntireGroup": change_group
        }

        return await self._handle_acc_id_list(
            "post",
            lambda acc_id: f"API/Accounts/{acc_id}/Change",
            await self.get_account_id(account),
            data
        )

    async def reconcile(self, account: Union[PrivilegedAccount, str]):
        """
        | This function set the account (or list) for immediate reconciliation.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If reconciliation failed
        """
        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/Reconcile",
            await self.get_account_id(account)
        )

    async def verify(self, account: Union[PrivilegedAccount, str]):
        """
        | This function set the account (or list) for immediate verification.
        | Keep in mind that for list, exceptions are returned and not raised.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: A boolean that indicates if the operation was successful.
        :raises CyberarkException: If verify failed
        """
        return await self._handle_acc_id_list(
            "post",
            lambda a: f"API/Accounts/{a}/Verify",
            await self.get_account_id(account)
        )

    def is_valid_username(self, username: str) -> bool:
        """ Check if the username is a valid Vault username

        :param username: username to check
        :return: A boolean that indicates whether the username if valid or not.
        """
        special_chars = "\\/.:*?\"<>|\t\r\n\x1F"
        return not (len(username) > 128 or any(c in special_chars for c in username))

    def is_valid_safename(self, name: str) -> bool:
        """ Check if the safename is a valid Vault safe name.

        :param name: Safe name to check
        :return: A boolean that indicates whether the username if valid or not.
        """
        special_chars = "\\/.:*?\"<>|\t\r\n\x1F"
        return not (len(name) > 28 or any(c in special_chars for c in name))

    async def search_account_by_ip_addr(self, address: Union[PrivilegedAccount, str]):
        """
        This function will search an account by IP address by checking if “address” is a valid IPv4 address
        and checking if “Address” property of the account is exactly the given address.
        You can also provide an PrivilegedAccount, the function will search on its address property

        :param address: A PrivilegedAccount object or IPv4 valid address
        :return: A list of "PrivilegedAccount" objects
        """
        if type(address) is str:
            address = address
        elif isinstance(address, PrivilegedAccount):
            address = address.address
        else:
            raise TypeError("search address function returned : First argument of address is not valid")

        if not validate_ip(address):
            raise TypeError(f"The address of the object was not considered as valid IPv4 address {address}")

        return await self.search_account_by(address=address)

    async def search_account(self, expression: str):
        """
        This function search an address using free text search and return a list a Privileged Account objects

        :param expression: List of keywords to search for in accounts, separated by a space.
        :return: List of PrivilegedAccount objects

        ℹ️ See also search_account_by function
        """
        return await self.search_account_by(expression)

    async def search_account_by(self, keywords=None, username=None, address=None, safe=None,
                                platform=None, **kwargs) -> List[PrivilegedAccount]:
        """search_account_by(keywords=None, username=None, address=None, safe=None, platform=None, **kwargs) -> list
        | This function allow to search using one or more parameters and return list of address id.
        | This is the easiest way to retrieve accounts from the vault.
        | It allows you to either search on given keywords, or more precisely on an account attribute.

        For example::

            accounts = await search_account_by(username="admin", safe="Linux-SRV", my_custom_FC="Database")

        :param keywords: free search
        :param username: username search (field "userName")
        :param address: IP address search (field "address")
        :param safe: search in particular safe
        :param platform: search by platform name (no space) (field "platformId")
        :param kwargs: any searchable key = value

        :return: A list of PrivilegedAccounts

        ⚠️ **Note**: This function doesn’t populate the secret field (password), you have to make a separated call if you
        want to get it.

        """

        return [account async for account in
                self.search_account_iterator(keywords, username, address, safe, platform, **kwargs)]

    async def search_account_iterator(self, keywords=None, username=None, address=None, safe=None,
                                      platform=None, **kwargs) -> AsyncIterator[PrivilegedAccount]:
        """
        | This function allow to search using one or more parameters and return list of address id.

        :param keywords: free search
        :param username: username search (field "userName")
        :param address: IP address search (field "address")
        :param safe: search in particular safe
        :param platform: search by platform name (no space) (field "platformId")
        :param kwargs: any searchable key = value

        :return: an async generator of PrivilegedAccounts

        ℹ️ See also search_account_by
        """

        filtered_args = {k: v for k, v in locals().items() if v and k not in ["safe", "self", "keywords", "kwargs"]}
        filtered_args.update(kwargs)

        page = 1
        has_next_page = True

        while has_next_page:
            accounts = await self.search_account_paginate(page=page, safe=safe, search=keywords, **filtered_args)
            has_next_page = accounts["has_next_page"]
            page += 1
            for a in accounts["accounts"]:
                yield a

    async def search_account_paginate(self, page: int = 1, size_of_page: int = 1000, safe: str = None,
                                      search: str = None, **kwargs):
        """
        Search accounts in a paginated way

        :param search: free search
        :param page: The page number (starting at 1)
        :param size_of_page: the size of pages (max 1000)
        :param safe: the safe name, if wanted
        :param kwargs: whatever file category you want to find
        :return:
            A dictionary with keys:

            - accounts : This is a list of matched account for the given page
            - has_next_page : A boolean hat indicated if there is a next page

        ℹ️ For your convenience you can use platform=”PF-NAME” instead of platformID (and thus if you have a custom
        “platform” FC it will not be considered).
        """

        try:
            params = {"search": " ".join(kwargs.values())}
        except TypeError as err:
            raise AiobastionException(f"You can't search on a list here ({kwargs.values()}), "
                                      "provide a string instead") from err

        if search is not None:
            params["search"] += f" {search}"

        if safe is not None:
            params["filter"] = "safeName eq " + safe

        params["limit"] = size_of_page
        params["offset"] = (page - 1) * size_of_page
        search_results = await self.epv.handle_request("get", "API/Accounts", params=params,
                                                       filter_func=lambda x: x)
        account_list = search_results['value']
        # check for each address if the content of FC match the search
        filtered_account_list = filter(lambda f: _filter_account(f, kwargs), account_list)
        # for each filtered address, build the PrivilegedAccount
        filtered_acc_list = [PrivilegedAccount(**acc) for acc in filtered_account_list]

        has_next_page = "nextLink" in search_results
        return {
            "accounts": filtered_acc_list,
            "has_next_page": has_next_page
        }

    async def connect_using_PSM(self, account, connection_component, reason: str = ""):
        """ This function returns a file content (bytes) which is the equivalent RDP file of the “Connect” button

        For example::

            async with production_vault as epv:
                # find first active connexion component
                try:
                    unique_id = await epv.platform.get_target_platform_unique_id(account.platformId)
                    ccs = await epv.platform.get_target_platform_connection_components(unique_id)
                    cc = None
                    for _cc in ccs:
                        if _cc["Enabled"]:
                            cc = _cc["PSMConnectorID"]
                            break
                except CyberarkException as err:
                    # You are not Vault Admin
                    self.assertIn("PASWS041E", str(err))

                rdp_content = await epv.account.connect_using_PSM(account.id, cc)
                with open("connect_account.rdp", "w") as rdp_file:
                    rdp_file.write(rdp_content)

        :param account: PrivilegedAccount or account_id
        :param connection_component: the connection component to connect with
        :param reason: the reason that is required to request access to this account
        :return: file_content
        :raises CyberarkAPIException:  if an error occured
        """
        account_id = await self.get_account_id(account)
        url, head = self.epv.get_url(f"API/Accounts/{account_id}/PSMConnect")
        head["Accept"] = 'RDP'
        body = {"ConnectionComponent": connection_component}
        if reason: body["Reason"] = reason

        async with aiohttp.ClientSession(headers=head, cookies = self.epv.cookies) as session:
            async with session.post(url, json=body, **self.epv.request_params) as req:
                if req.status != 200:
                    content = await req.json()
                    raise CyberarkAPIException(req.status, content["ErrorCode"], content["ErrorMessage"])

                return await req.read()

    async def disable_password_management(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                          reason: str = ""):
        """ This disables the account (or list) password management

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reason: The reason of disabling password management (defaults to empty string)
        :return: The list of updated accounts, or exceptions
        :raises CyberarkException: If disabling failed.
        """
        data = [
            {"op": "replace", "path": "/secretManagement/automaticManagementEnabled", "value": False},
            {"op": "add", "path": "/secretManagement/manualManagementReason", "value": reason}
        ]

        _results = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )
        # Single item
        if isinstance(_results, dict):
            return PrivilegedAccount(**_results)
        # list
        else:
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in _results]

    async def resume_password_management(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """ This resume the account (or list) password management

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The list of updated accounts, or exceptions
        :raises CyberarkException: If resuming failed.
        """

        data = [
            {"op": "replace", "path": "/secretManagement/automaticManagementEnabled", "value": True},
        ]
        _results = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )

        # Single item
        if isinstance(_results, dict):
            return PrivilegedAccount(**_results)
        # list
        else:
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in _results]
        # return await self.epv.handle_request("patch", f"API/Accounts/{account_id}", data=data)

    async def update_using_list(self, account, data) -> Union[PrivilegedAccount, List[PrivilegedAccount]]:
        """ **This function support list of PrivilegedAccount as argument**

        | This function updates an account (or list) with the data list of changes. For more infos, check CyberArk doc.
        | Valid operations are : Replace, Remove or Add

        For example::

            # insert here logon to vault and retrieve an account
            data = [
                {"path": "/name", "op": "replace", "value": new_name},
                {"path": "/address", "op": "replace", "value": new_address},
                {"path": "/platformId", "op": "replace", "value": new_platformId},
            ]
            is_updated = await epv.account.update_using_list(account, data)


        :param account: address, list of accounts, account_id, list of accounts id
        :param data: The list of FC to change.

        :return: The updated PrivilegedAccount or the list of updated PrivilegedAccount
        """
        updated_accounts = await self._handle_acc_id_list(
            "patch",
            lambda account_id: f"API/Accounts/{account_id}",
            await self.get_account_id(account),
            data
        )
        if isinstance(updated_accounts, dict):
            return PrivilegedAccount(**updated_accounts)
        else:
            # Will return exception if met
            return [PrivilegedAccount(**r) if isinstance(r, dict) else r for r in updated_accounts]
            # return [PrivilegedAccount(**u) for u in updated_accounts]

    def detect_fc_path(self, fc: str):
        """
        Detect the path of the File Category

        :param fc: the name of the File Category
        :return: The string representing the Path to the FC
        """
        if fc in BASE_FILECATEGORY:
            return "/"
        elif fc in SECRET_MANAGEMENT_FILECATEGORY:
            return "/secretmanagement/"
        else:
            return "/platformaccountproperties/"

    async def update_single_fc(self,  account, file_category, new_value, operation="replace"):
        """
        Update / Delete / Create a File Category for an account or a list of accounts
        The path of the file_category is (hopefully) automatically detected

        :param account: address, list of accounts, account_id, list of accounts id
        :param file_category: the File Category to update
        :param new_value: The new value of the FC
        :param operation: Replace, Remove or Add
        :return: The updated PrivilegedAccount or the list of updated PrivilegedAccount
        :raises AiobastionException: if the FC was not found in the Vault
        :raises CyberarkAPIException: if another error occured
        """
        # if we "add" and FC exists it will replace it
        data = [{"path": f"{self.detect_fc_path(file_category)}{file_category}", "op": operation, "value": new_value}]
        try:
            return await self.update_using_list(account, data)
        except CyberarkAPIException as err:
            if err.err_code == "PASWS164E" and operation == "replace":
                # Try to add FC instead of replacing it
                return await self.update_single_fc(account, file_category, new_value, "add")
            if err.http_status == 400:
                raise AiobastionException("The FC was not found in the Vault (it is case sensitive)") from err
            else:
                raise

    async def update_file_category(self, account, file_category, new_value):
        """
        Update the file category (or list of FC) with the new value (or list of new values)
        If the FC does not exist, it will create it

        :param account: address, list of accounts, account_id, list of accounts id
        :param file_category: a file category or a list of file category
        :param new_value: the new value of the list of new values

        """
        data = []
        if isinstance(file_category, list):
            try:
                assert isinstance(new_value, list)
            except AssertionError:
                raise AiobastionException("If file_category is a list, then new value must be a list as well")
            try:
                assert len(file_category) == len(new_value)
            except AssertionError:
                raise AiobastionException("You must provide the same list size for file_category and values")
            for f,n in zip(file_category, new_value):
                # we trust user and don't check if FC is defined at platform level
                data.append({"path": f"{self.detect_fc_path(f)}{f}", "op": "add", "value": n})
        else:
            data.append({"path": f"{self.detect_fc_path(file_category)}{file_category}", "op": "add", "value": new_value})

        return await self.update_using_list(account, data)


    async def restore_last_cpm_version(self, account: PrivilegedAccount, cpm):
        """
        Find in the history of passwords the last password set by the CPM and updates the password accordingly
        in the Vault

        :param account: a PrivilegedAccount object
        :param cpm: the name of the CPM who set the password
        :return: True if success
        :raises AiobastionException: if no CPM version was found
        """
        versions = await self.get_secret_versions(account)
        cpm_versions = [v["versionID"] for v in versions if v["modifiedBy"] == cpm]
        if len(cpm_versions) > 0:
            good_ver = max(cpm_versions)
            password_to_set = await self.get_secret_version(account, good_ver)
            return await self.set_password(account,password_to_set)
        else:
            raise AiobastionException("There is no CPM version for this account")

    async def restore_last_cpm_version_by_cpm(self, account: PrivilegedAccount, cpm):
        """
        Find in the history of passwords the last password set by the CPM and schedule a password change with this value

        :param account: a PrivilegedAccount object
        :param cpm: the name of the CPM who set the password
        :return: True if success
        :raises AiobastionException: if there is no CPM version for this account
        """
        versions = await self.get_secret_versions(account)
        cpm_versions = [v["versionID"] for v in versions if v["modifiedBy"] == cpm]
        if len(cpm_versions) > 0:
            good_ver = max(cpm_versions)
            password_to_set = await self.get_secret_version(account, good_ver)
            return await self.set_next_password(account, password_to_set)
        else:
            raise AiobastionException("There is no CPM version for this account")

    async def get_secret_version(self, account: PrivilegedAccount, version: int, reason: str = None):
        """
        Get the version of a password

        :param account: a PrivilegedAccount object
        :param version: the version ID (that you can find with get_secret_versions). The higher is the most recent.
        :param reason: The reason that is required to retrieve the password
        :return: the secret
        :raises CyberarkException: if the version was not found
        """
        if version < 1:
            raise AiobastionException("The version must be a non-zero natural integer")

        data = {"Version": version}
        if reason: data["Reason"] = reason
        account_id = await self.get_account_id(account)

        url = f"API/Accounts/{account_id}/Password/Retrieve"

        return await self.epv.handle_request("post", url, data=data)

    async def get_password(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]], reason: str = None):
        """
        | Retrieve the password of an address
        | ✅ Use get_secret instead if you want to retrieve password or ssh_key

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param reason: The reason that is required to retrieve the password
        :return: Account password value  (or list of passwords)
        :raises CyberarkException: If retrieve failed
        """
        data = {}
        if reason: data = {"Reason": reason}
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Password/Retrieve",
            await self.get_account_id(account),
            data = data
        )


    # Test me
    async def get_ssh_key(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Retrieve the SSH Key of an account

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: SSH key value, or a list of ssh key values
        """

        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Secret/Retrieve",
            await self.get_account_id(account)
        )

    async def get_secret_versions(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]], reason: str = None):
        """
        Retrieve the secret versions

        :param account: Privileged Account or address id
        :param reason: The reason that is required to retrieve the password
        :return: Account password value
        """
        data = {}
        if reason: data = {"Reason": reason}
        versions = await self._handle_acc_id_list(
            "get",
            lambda account_id: f"API/Accounts/{account_id}/Secret/Versions/",
            await self.get_account_id(account),
            data = data
        )

        if isinstance(versions, list):
            return [v["Versions"] for v in versions]
        elif isinstance(versions, dict):
            return versions["Versions"]
        else:
            raise AiobastionException(versions)

    # Test
    async def get_secret(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """
        Get the secret of an account, detecting if the secret type is password or key

        :param account: A PrivilegedAccount object, or a list of PrivilegedAccount objects
        :return: The password, key or list of passwords / keys.
        """
        if isinstance(account, list):
            tasks = []
            for a in account:
                if a.secretType == "key":
                    tasks.append(self.get_ssh_key(a))
                else:
                    tasks.append(self.get_password(a))
            return await asyncio.gather(*tasks)
        else:
            if account.secretType == "key":
                return await self.get_ssh_key(account)
            else:
                return await self.get_password(account)

    async def set_password(self, account, password):
        """
        Set the password for the given address **in the Vault**

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param password: new password to set
        :return: True if success
        :raises CyberarkException: If set password failed (your platform enforce complexity, or you don’t have rights)
        """
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/Password/Update",
            await self.get_account_id(account),
            {"NewCredentials": password}
        )

    async def set_next_password(self, account, password):
        """
        Set the next password for the given address to be set by the CPM

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param password: new password to set
        :return: True if change was successfully planned.
        """
        return await self._handle_acc_id_list(
            "post",
            lambda account_id: f"API/Accounts/{account_id}/SetNextPassword",
            await self.get_account_id(account),
            {"ChangeImmediately": True, "NewCredentials": password}
        )

    async def delete(self, account: Union[PrivilegedAccount, str, List[PrivilegedAccount], List[str]]):
        """ **This function support list of PrivilegedAccount as argument**

        | This deletes the account (or list).
        | ⚠️ If this is an SSH Key, this function will delete it on the Vault but not on systems!

        :param account: PrivilegedAccount or list(PrivilegedAccount) to delete
        :return: True if succeeded
        :raises CyberarkException: If delete failed
        """
        # account_id = await self.get_account_id(address),
        async def api_call(account_id):
            try:
                return await self.epv.handle_request("delete", f"API/Accounts/{account_id}")
            except CyberarkAPIException:
                return await self.epv.handle_request("delete", f"WebServices/PIMServices.svc/Accounts/{account_id}")

        return await self._handle_acc_list(
            api_call,
            await self.get_account_id(account)
        )

    async def get_cpm_status(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | Get the CPM status of an account or a list of accounts.
        | ✅ You can also use the cpm_status() method of the object PrivilegedAccount

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The secretManagement dictionary of the account.
        """
        if isinstance(account, list):
            return [a.secretManagement for a in account]
        else:
            return account.secretManagement

    async def activity(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        Get account(s) activity

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The activity dictionary as-is it is returned by CyberArk
        :raises CyberarkException: If call failed
        """
        activities = await self._handle_acc_id_list(
            "get",
            lambda account_id: f"WebServices/PIMServices.svc/Accounts/{account_id}/Activities/",
            await self.get_account_id(account)
        )

        if isinstance(activities, list):
            return [a["GetAccountActivitiesSlashResult"] for a in activities]
        elif isinstance(activities, dict):
            return activities["GetAccountActivitiesSlashResult"]
        else:
            return None

    async def last_cpm_error_message(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        Get the last CPM Error message

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: The last CPM error status, or None
        :raises CyberarkException: If link failed
        """
        activities = await self.activity(account)

        def single_cpm_error(activity):
            """
            Get the very last error for an activity dict

            :param activity: The CyberArk activity dict
            :return: The last CPM error if any
            """
            for a in activity:
                if "CPM" in a["Activity"]:
                    if "Failure" in a["Reason"]:
                        reason = a["Reason"].split("Error:")
                        return reason[1]

        # List of list
        if any(isinstance(el, list) for el in activities):
            return [single_cpm_error(_activity) for _activity in activities]
        else:
            return single_cpm_error(activities)

    async def add_member_to_group(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]],
                                  group_name: str = "") -> str:
        """ **This function support list of PrivilegedAccount as argument**
        Add an address to a group

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list

        :param group_name: name of the group (or try the address username if empty)
        :return: AccountID
        """
        groups = await self.epv.accountgroup.list_by_safe(account.safeName)
        group_id = 0
        if group_name == "":
            for group in groups:
                if account.userName.lower() in group.name.lower():
                    group_id = group.id
        else:
            for group in groups:
                if group_name.lower() == group.name.lower():
                    group_id = group.id
        if group_id == 0:
            raise AiobastionException("Group name was incorrect or not found")

        async def _api_call(acc):
            url = f"API/AccountGroups/{group_id}/Members"
            data = {"AccountId": acc.id}
            return await self.epv.handle_request("post", url, data=data)

        return await self._handle_acc_list(
            _api_call,
            account
        )

    async def get_account_group(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """
        | Returns the GroupID of a given PrivilegedAccount
        | To get the group name, and more, check the Account Group section of this documentation.

        :param account: PrivilegedAccount, list of Privileged Accounts
        :type account: PrivilegedAccount, list
        :return: GroupID (which is not the group name)
        """

        async def _api_call(acc):
            for group in await self.epv.accountgroup.list_by_safe(acc.safeName):
                groupid = group.id
                for member in await self.epv.accountgroup.members(groupid):
                    if member.id == acc.id:
                        return groupid
            return None

        return await self._handle_acc_list(_api_call, account)

    async def del_account_group_membership(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]]):
        """ Find and delete the account_group membership of a PrivilegedAccount (or list)

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :return: False if no group was remove, True is a group was deleted
        :raises CyberarkAPIException: if a group was found but deletion didn't work
        """

        async def _del_accountgroup(acc):
            groupid = await self.get_account_group(acc)
            if groupid is None:
                return False
            else:
                try:
                    await self.epv.accountgroup.delete_member(acc, groupid)
                except Exception as err:
                    raise CyberarkException("Unable to remove address group " + str(err))
                return True

        return await self._handle_acc_list(_del_accountgroup, account)

    async def update_platform(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], new_platform: str):
        """ This function updates the account’s (or list) platform

        :param account: PrivilegedAccount, list of Privileged Accounts
        :param new_platform: The new plaform ID (e.g. Unix-SSH)
        :return: True if succeeded
        """

        data = [{"path": "/platformID", "op": "replace", "value": new_platform}]
        return await self.epv.account.update_using_list(account, data)

    async def move(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], new_safe: str):
        """ Delete the account (or list) and recreate it (or them) in with the same parameters and password in the new
        safe.

        :param account: a PrivilegedAccount object or a list of PrivilegedAccount objects
        :type account: PrivilegedAccount, list
        :param new_safe: New safe to move the account(s) into
        :return: Boolean that indicates if the operation was successful
        """
        async def _move(acc):
            self.epv.logger.debug(f"Now trying to move {acc} to {new_safe}")
            old_id = acc.id
            acc.safeName = new_safe
            try:
                acc.secret = await self.get_password(acc)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to recover {acc.name} password : {str(err)}")
            try:
                new_account_id = await self.add_account_to_safe(acc)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to create {acc.name} new address : {str(err)}")
            try:
                await self.delete(old_id)
            except CyberarkAPIException as err:
                raise CyberarkException(f"Unable to delete {acc.name} old address : {str(err)}")
            return new_account_id

        return await self._handle_acc_list(_move, account)

    # AIM get secret function
    async def get_secret_aim(self, account: Union[PrivilegedAccount, List[PrivilegedAccount]], reason: str = None):
        """ **This function support list of PrivilegedAccount as argument**

        | This function update the secret attribute of the PrivilegedAccount with the password
          returned by the **AIM Web service**. If the account is not found, the secret is set to None.

        :param account: A PrivilegedAccount object, or a list of PrivilegedAccount objects
        :param reason: The reason for retrieving the password. This reason will be audited in the Credential
            Provider audit log. (optional)
        :type account: PrivilegedAccount, list
        :return: PrivilegedAccount Object updated, if the password is not found the secret will be None
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :raise AiobastionException: AIM configuration setup error
        """
        if self.epv.AIM is None:
            raise AiobastionException(
                    "Missing AIM information to perform AIM authentication, see documentation")

        if isinstance(account, list):
            tasks = []
            for acc in account:
                if not acc.secretType or (acc.secretType and acc.secretType == "password"):
                    tasks.append(self.get_secret_aim(acc, reason))
            return await asyncio.gather(*tasks)

        # Deal with a single account
        if not isinstance(account, PrivilegedAccount):
            raise AiobastionException("You must provide a valid PrivilegedAccount.")

        params={"object": account.name }

        if reason:
            params["reason"] = reason
        if account.safeName:
            params["safe"] = account.safeName

        try:
            account.secret = await self.epv.AIM.get_secret(**params)

        except CyberarkAIMnotFound:
            account.secret = None

        return account


    async def get_password_aim(self, **kwargs):
        """
        | Retrieve secret password from the Central Credential Provider (**AIM**) GetPassword
          Web Service information.

        | ℹ️ The following parameters are optional searchable keys. Refer to
            `CyberArk Central Credential Provider - REST web service`.

        :param username: User account name
        :param safe: Safe where the account is stored.
        :param object: Name of the account to retrieve (unique for a specific safe).
        :param folder: Name of the folder property
        :param address: Address account property
        :param database: Database account property
        :param policyid: Policy account property
        :param reason: The reason for retrieving the password. This reason will be audited in the Credential
            Provider audit log.
        :param query: Defines a free query using account properties, including Safe, folder, and object.
            When this method is specified, all other search criteria
            (Safe/Folder/ Object/UserName/Address/PolicyID/Database) are ignored and only the
            account properties that are specified in the query are passed to the Central
            Credential Provider in the password request.
        :param queryformat: Defines the query format, which can optionally use regular expressions.
            Possible values are: Exact or Regexp
        :param failrequestonpasswordchange: Boolean, Whether or not an error will be returned if
            this web service is called when a password change process is underway.
        :return:  namedtuple of (secret, detail)

        |            secret = password
        |            detail = dictionary from the Central Credential Provider (AIM) GetPassword Web
                               Service.

        :raise CyberarkAIMnotFound: Account not found
        :raise CyberarkAPIException: HTTP error or CyberArk error
        :raise CyberarkException: Runtime error
        :raise AiobastionException: AIM configuration setup error
        """
        if self.epv.AIM is None:
            raise AiobastionException(
                    "Missing AIM information to perform AIM authentication, see documentation")

        return await self.epv.AIM.get_secret_detail(**kwargs)
>>>>>>> d06df4a570e5fc5f0b18a46849d1a5b0932898da
