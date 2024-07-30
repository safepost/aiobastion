# -*- coding: utf-8 -*-
import warnings
from typing import AsyncIterator, Union

from .config import permissions, DEFAULT_PERMISSIONS, get_v2_profile, validate_integer
from .exceptions import (
    CyberarkAPIException, CyberarkException, AiobastionException, AiobastionConfigurationException
)


class Safe:
    _SAFE_DEFAULT_CPM = ""
    _SAFE_DEFAULT_RETENTION = 10

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = ["cpm", "retention"]

    def __init__(self, epv, cpm = None, retention = None):
        self.epv       = epv
        self.cpm       = cpm if cpm is not None else Safe._SAFE_DEFAULT_RETENTION
        self.retention = retention if retention is not None else Safe._SAFE_DEFAULT_RETENTION


    @classmethod
    def _init_validate_class_attributes(cls, serialized: dict, section: str, configfile: str = None) -> dict:
        """_init_validate_class_attributes      Initialize and validate the Safe definition (file configuration and serialized)

        Arguments:
            serialized {dict}           Definition from configuration file or serialization
            section {str}               Verified section name

        Keyword Arguments:
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Returns:
            new_serialized {dict}       Safe defintion
        """
        if configfile:
            configfile = "serialized"

        new_serialized = {
            "cpm": Safe._SAFE_DEFAULT_CPM,
            "retention":  Safe._SAFE_DEFAULT_RETENTION
            }

        for k in serialized.keys():
            keyname = k.lower()

            try:
                # Special validation: integer, boolean
                if keyname == "retention":
                    new_serialized[keyname] = validate_integer(configfile, f"{section}/{keyname}", serialized[k])
                elif keyname in Safe._SERIALIZED_FIELDS:
                    # String definition
                    if serialized[k] is not None:
                        new_serialized[keyname] = serialized[k]
                else:
                    raise AiobastionConfigurationException(f"Unknown attribute '{section}/{k}' in {configfile}")

            except ValueError:
                raise(f"Invalid integer definition '{section}/{k}' in {configfile}: {serialized[k]!r}")


        new_serialized.setdefault("cpm", Safe._SAFE_DEFAULT_CPM)
        new_serialized.setdefault("retention", Safe._SAFE_DEFAULT_RETENTION)

        return new_serialized


    def to_json(self):
        serialized = {}

        for attr_name in Safe._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized


    # TODO : add membershipExpirationDate permissions isReadOnly
    async def add_member(self, safe: str, username: str, search_in: str = "Vault",
                         useAccounts: bool = False,
                         retrieveAccounts: bool = False,
                         listAccounts: bool = False,
                         addAccounts: bool = False,
                         updateAccountContent: bool = False,
                         updateAccountProperties: bool = False,
                         initiateCPMAccountManagementOperations: bool = False,
                         specifyNextAccountContent: bool = False,
                         renameAccounts: bool = False,
                         deleteAccounts: bool = False,
                         unlockAccounts: bool = False,
                         manageSafe: bool = False,
                         manageSafeMembers: bool = False,
                         backupSafe: bool = False,
                         viewAuditLog: bool = False,
                         viewSafeMembers: bool = False,
                         accessWithoutConfirmation: bool = False,
                         createFolders: bool = False,
                         deleteFolders: bool = False,
                         moveAccountsAndFolders: bool = False,
                         requestsAuthorizationLevel1: bool = False,
                         requestsAuthorizationLevel2: bool = False
                         ):
        """
        Add a safe member

        :param safe: Name of the safe - Required
        :param username: Name of the user or group to add - Required
        :param search_in: The Vault or the domain of the user or group - Defaults to Vault - Optional
        :param useAccounts: Use accounts but cannot view passwords. - Default: False - Optional
        :param retrieveAccounts: Retrieve and view accounts in the Safe. - Default: False - Optional
        :param listAccounts: View accounts list. - Default: False - Optional
        :param addAccounts: Add accounts in the Safe. - Default: False - Optional
        :param updateAccountContent: Update existing account content. - Default: False - Optional
        :param updateAccountProperties: Update existing account properties. - Default: False - Optional
        :param initiateCPMAccountManagementOperations: Initiate password management operations through CPM. - Default: False - Optional
        :param specifyNextAccountContent: Specify the password that is used when the CPM changes the password value. - Default: False - Optional
        :param renameAccounts: Rename existing accounts in the Safe. - Default: False - Optional
        :param deleteAccounts: Delete existing passwords in the Safe. - Default: False - Optional
        :param unlockAccounts: Unlock accounts that are locked by other users. - Default: False - Optional
        :param manageSafe: Perform administrative tasks in the Safe (update properies, recover, delete) - Default: False - Optional
        :param manageSafeMembers: Add and remove Safe members, and update their authorizations in the Safe. - Default: False - Optional
        :param backupSafe: Create a backup of a Safe and its contents, and store it in another location. - Default: False - Optional
        :param viewAuditLog: View account and user activity in the Safe. - Default: False - Optional
        :param viewSafeMembers: View permissions of Safe members. - Default: False - Optional
        :param accessWithoutConfirmation: Access the Safe without confirmation from authorized users. - Default: False - Optional
        :param createFolders: Create folders in the Safe. - Default: False - Optional
        :param deleteFolders: Delete folders in the Safe. - Default: False - Optional
        :param moveAccountsAndFolders: Move accounts and folders in the Safe to different folders and subfolders. - Default: False - Optional
        :param requestsAuthorizationLevel1: Request Authorization Level 1. - Default: False - Optional
        :param requestsAuthorizationLevel2: Request Authorization Level 2. - Default: False - Optional
        :return: A dict with the result
        """
        perm = {
            "useAccounts": useAccounts,
            "retrieveAccounts": retrieveAccounts,
            "listAccounts": listAccounts,
            "addAccounts": addAccounts,
            "updateAccountContent": updateAccountContent,
            "updateAccountProperties": updateAccountProperties,
            "initiateCPMAccountManagementOperations": initiateCPMAccountManagementOperations,
            "specifyNextAccountContent": specifyNextAccountContent,
            "renameAccounts": renameAccounts,
            "deleteAccounts": deleteAccounts,
            "unlockAccounts": unlockAccounts,
            "manageSafe": manageSafe,
            "manageSafeMembers": manageSafeMembers,
            "backupSafe": backupSafe,
            "viewAuditLog": viewAuditLog,
            "viewSafeMembers": viewSafeMembers,
            "accessWithoutConfirmation": accessWithoutConfirmation,
            "createFolders": createFolders,
            "deleteFolders": deleteFolders,
            "moveAccountsAndFolders": moveAccountsAndFolders,
            "requestsAuthorizationLevel1": requestsAuthorizationLevel1,
            "requestsAuthorizationLevel2": requestsAuthorizationLevel2
        }

        url = f"api/Safes/{safe}/Members"

        data = {
            'MemberName': username,
            'Permissions': perm,
            'searchIn': search_in
        }

        if not await self.exists(safe):
            raise AiobastionException(f"Safe : \"{safe}\" was not found")

        return await self.epv.handle_request("post", url, data=data)

    # TODO : Document profiles
    async def add_member_profile(self, safe: str, username: str, profile: Union[str, dict]):
        """
        This functions adds the "username" user (or group) to the given safe with a relevant profile

        :param safe: The safe name
        :param username: the username or a group name
        :param profile: must be one of "admin", "use", "show", "audit", "prov", "manager", "power" or "cpm"
        :return: boolean
        """
        if isinstance(profile, str):
            assert profile.lower() in ["admin", "use", "show", "audit", "prov", "power", "cpm", "manager"]
            perm = permissions(profile)
        else:
            # ensure there is at least one right for the safe username
            assert any(k in profile.keys() for k in DEFAULT_PERMISSIONS.keys())
            perm = profile

        url = f"api/Safes/{safe}/Members"

        data = {
            'MemberName': username,
            'Permissions': perm
        }

        return await self.epv.handle_request("post", url, data=data)

    async def remove_member(self, safe: str, username: str):
        """
        Remove a user or a group from a safe

        :param safe: The safe name
        :param username: The user or group name
        :return: Boolean
        """
        url = f"api/Safes/{safe}/Members/{username}"
        return await self.epv.handle_request("delete", url)

    async def exists(self, safename: str):
        """
        Whether a safe exists whose name is "safename"

        :param safename: name of the safe
        :return: Boolean
        """
        if safename == "":
            return False

        url = f"api/Safes/{safename}"
        try:
            req = await self.epv.handle_request("get", url)
        except CyberarkException:
            return False
        return safename == req["safeName"]

    async def add(self, safe_name: str, description="", location="", olac=False, days=-1, versions=None,
                  auto_purge=False, cpm=None, add_admins=True):
        """
        Creates a new safe

        :param safe_name: The name of the safe to create
        :param description: The safe description
        :param location: Safe location (must be an existing location)
        :param olac: Enable OLAC for the safe (default to False)
        :param days: days of retention
        :param versions: number of versions
        :param auto_purge: Whether to automatically purge files after the end of the Object History Retention Period defined in the Safe properties.
        :param cpm: The name of the CPM user who will manage the new Safe.
        :param add_admins: Add "Vaults Admin" group and Administrator user as safe owners
        :return: boolean
        """

        url = f"api/Safes"
        data = {
            "SafeName": safe_name,
            "Description": description,
            "OLACEnabled": olac,
            "ManagingCPM": self.cpm if cpm is None else cpm,
            "NumberOfVersionsRetention": self.retention if versions is None else versions,
            "numberOfDaysRetention": days,
            "AutoPurgeEnabled": auto_purge,
            "location": location
        }

        # options are mutually exclusive
        if days >= 0:
            data.pop("NumberOfVersionsRetention", None)
        else:
            data.pop("numberOfDaysRetention", None)

        ret = await self.epv.handle_request("post", url, data=data)

        if add_admins:
            await self.add_defaults_admin(safe_name)

        return ret

    async def add_defaults_admin(self, safe_name):
        """
        Add "Vaults Admin" group and Administrator user as safe owners

        :param safe_name: Name of the safe
        :return: boolean
        """
        # Define Safe defaults owners
        for user, profile in {"Vault Admins": "admin", "Administrator": 'admin'}.items():
            try:
                await self.add_member_profile(safe_name, user, profile)
            except CyberarkAPIException as err:
                if err.http_status == 409:
                    warnings.warn(err.err_message)
                    # pass
                elif err.http_status == 403:
                    warnings.warn(err.err_message)
                else:
                    raise

    async def delete(self, safe_name):
        """
        Delete the safe

        :param safe_name: Name of the safe
        :return: Boolean
        """
        url = f"api/Safes/{safe_name}"
        return await self.epv.handle_request("delete", url)

    async def list_members(self, safe_name: str, filter_perm=None, details=False, raw=False):
        """
        List members of a safe, optionally those with specific perm

        :param raw: if True, return the API content directly (filter_perm and details are ignored)
        :param details: If True, return a dict with more infos on each username
        :param safe_name: Name of the safe
        :param filter_perm: Specific perm, for example "ManageSafe", refer to doc for more
        :return: list of all users, or list of users with specific perm
        """
        if filter_perm is not None:
            # valid_filter = ['Add', 'AddRenameFolder', 'BackupSafe', 'Delete', 'DeleteFolder', 'ListContent',
            #                 'ManageSafe', 'ManageSafeMembers', 'MoveFilesAndFolders', 'Rename',
            #                 'RestrictedRetrieve', 'Retrieve', 'Unlock', 'Update', 'UpdateMetadata',
            #                 'ValidateSafeContent', 'ViewAudit', 'ViewMembers']
            # v2 API
            valid_filter = ['useAccounts', 'retrieveAccounts', 'listAccounts', 'addAccounts', 'updateAccountContent',
                            'updateAccountProperties', 'initiateCPMAccountManagementOperations',
                            'specifyNextAccountContent', 'renameAccounts', 'deleteAccounts', 'unlockAccounts',
                            'manageSafe', 'manageSafeMembers', 'backupSafe', 'viewAuditLog', 'viewSafeMembers',
                            'accessWithoutConfirmation', 'createFolders', 'deleteFolders', 'moveAccountsAndFolders',
                            'requestsAuthorizationLevel1', 'requestsAuthorizationLevel2']
            if filter_perm not in valid_filter:
                raise AiobastionException(f"filter_perm {filter_perm} is not one of : {valid_filter} ")

        #url = f"WebServices/PIMServices.svc/Safes/{safe_name}/Members"
        url = f"api/Safes/{safe_name}/Members"
        try:
            members = await self.epv.handle_request("get", url, filter_func=lambda x: x["value"])
        except CyberarkException as err:
            raise CyberarkAPIException(404, "ERR_404", f"Safe {safe_name} doesn't exist")

        if raw:
            return members

        if details:
            if filter_perm is not None:
                return [{"username": m["memberName"],
                         "type": m["memberType"],
                         "isPredefinedUser": m["isPredefinedUser"],
                         "membershipExpirationDate": m["membershipExpirationDate"],
                         "profil": get_v2_profile(m["permissions"])
                         } for m in members if m["permissions"][filter_perm]]
            else:
                return [{"username": m["memberName"],
                         "type": m["memberType"],
                         "isPredefinedUser": m["isPredefinedUser"],
                         "membershipExpirationDate": m["membershipExpirationDate"],
                         "profil": get_v2_profile(m["permissions"])
                         } for m in members]
        else:
            if filter_perm is not None:
                return [m["memberName"] for m in members if m["permissions"][filter_perm]]
            else:
                return [m["memberName"] for m in members]

    async def is_member_of(self, safe_name: str, username: str) -> bool:
        """
        Whether the user is username of the safe

        :param safe_name: Name of the safe
        :param username: Name of the user (or group)
        :return: boolean
        """
        return username in await self.list_members(safe_name)

    async def search_safe_iterator(self, query=None, include_accounts=False, extended_details=False) -> AsyncIterator:
        """
        This function allow to search using one or more parameters and return list of address id

        :param query: free search
        :param include_accounts: include safe's accounts
        :return: an async iterator of json representation of safes
        """

        page = 1
        has_next_page = True

        while has_next_page:
            accounts = await self.search_safe_paginate(page=page, search=query, include_accounts=include_accounts,
                                                       extended_details=extended_details)
            has_next_page = accounts["has_next_page"]
            page += 1
            for a in accounts["accounts"]:
                yield a

    async def search_safe_paginate(self, page: int = 1, size_of_page: int = 100, search: str = None,
                                   include_accounts=False, extended_details=False):
        """
        Search safes in a paginated way

        :param search: free search
        :param page: number of page
        :param size_of_page: size of pages
        :param include_accounts: include safe's accounts
        :param extended_details: add more details on the safe (may be very slow)

        :return:

        """
        params = {}

        if search is not None:
            params["search"] = f"{search}"

        params["includeAccounts"] = str(include_accounts)
        params["extendedDetails"] = str(extended_details)


        params["limit"] = size_of_page
        params["offset"] = (page - 1) * size_of_page
        try:
            search_results = await self.epv.handle_request("get", "API/Safes", params=params,
                                                   filter_func=lambda x: x)
        except CyberarkAPIException as err:
            if err.err_code == "CAWS00001E":
                raise AiobastionException("Please don't list safes with a user member of PSMMaster (Cyberark bug)")
            else:
                raise
        safe_list = search_results['value']

        has_next_page = "nextLink" in search_results
        return {
            "accounts": safe_list,
            "has_next_page": has_next_page
        }

    async def search(self, query=None, include_accounts=False, details=False):
        """
        Search for a safe

        :param query: What to search - Default: None (retrieve all safes) - Optional
        :param include_accounts: Add privileged accounts on the result - Default: False - Optional
        :param details: Include additional safe details - Default: False - Optional
        :return: A list of dict with the result
        """
        return [safe async for safe in self.search_safe_iterator(query, include_accounts, details)]

    async def list(self, details=False):
        """
        List all safes (better use search)

        :return: A list of safes names
        """
        if details:
            return await self.search(details=True)
        else:
            return [r["safeName"] for r in await self.search()]

    async def get_safe_details(self, safename: str):
        """
        Get details of a given safe. We do a direct query instead of a search for efficiency.

        :return: A dict of the safe details
        """
        if not safename:
            raise AiobastionException("A safe name must be provided")
        return await self.epv.handle_request("get", f"API/Safes/{safename}", params={"extendedDetails": "True"})

    async def v1_get_safes(self):
        """
        Old way to retrieve safes, when the v2 operation fail

        :return: A list of safes
        """
        return await self.epv.handle_request("get", 'WebServices/PIMServices.svc/Safes/', filter_func=lambda r: r)

    async def get_permissions(self, safename: str, username: str):
        """
        Get a user (or group) permissions

        :param safename: Name of the safe
        :param username: Name of the user (or group)
        :return: list of permissions
        """
        url = f"api/Safes/{safename}/members/{username}"
        return await self.epv.handle_request("get", url, filter_func=lambda r: r["permissions"])

    async def rename(self, safename: str, new_name: str):
        """
        Rename a safe
        """
        found_safes = await self.search(safename, True, True)
        try:
            good_safe = next(_s for _s in found_safes if _s["safeName"].upper() == safename.upper())
        except StopIteration:
            raise AiobastionException(f"Safe {safename} was not found")
        # print(good_safe)
        safe_url_id = good_safe["safeUrlId"]
        url = f"API/Safes/{safe_url_id}/"

        # Update name in safe data
        good_safe["safeName"] = new_name

        return await self.epv.handle_request("put", url, data=good_safe)

    async def update(self, safe_name: str, description=None, location=None, olac=None, days=None, versions=None,
                     cpm=None):
        """
        Update existing safe

        :param safe_name: The name of the safe to update
        :param description: The safe description
        :param location: Safe location (must be an existing location)
        :param olac: Enable OLAC for the safe (default to False)
        :param days: Days of retention
        :param versions: Number of versions
        :param cpm: The name of the CPM user who will manage the new Safe.
        :return: A dict of the updated safe details
        """

        url = f"api/Safes/{safe_name}"
        data = {
            "SafeName": safe_name,
        }

        if description is not None:
            data["Description"] = description
        if location is not None:
            data["location"] = location
        if olac is not None:
            data["OLACEnabled"] = olac
        if days is not None:
            data["numberOfDaysRetention"] = days
        if versions is not None:
            data["NumberOfVersionsRetention"] = versions
        if cpm is not None:
            data["ManagingCPM"] = cpm

        # options are mutually exclusive
        if days is not None and days >= 0:
            data.pop("NumberOfVersionsRetention", None)
        else:
            data.pop("numberOfDaysRetention", None)

        return await self.epv.handle_request("put", url, data=data)
