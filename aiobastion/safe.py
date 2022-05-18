# -*- coding: utf-8 -*-

from .abstract import Vault
from .config import permissions, DEFAULT_PERMISSIONS, get_v2_profile
from .exceptions import (
    CyberarkAPIException, CyberarkException, AiobastionException
)


class Safe:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def add_member(self, safe: str, username: str, profile: (str, dict)):
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
        Return whether or not a safe exists

        :param safename: name of the safe
        :return: Boolean
        """
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
        :param auto_purge: Whether or not to automatically purge files after the end of the Object History Retention Period defined in the Safe properties.
        :param cpm: The name of the CPM user who will manage the new Safe.
        :param add_admins: Add "Vaults Admin" group and Administrator user as safe owners
        :return: boolean
        """

        url = f"api/Safes"
        data = {
            "SafeName": safe_name,
            "Description": description,
            "OLACEnabled": olac,
            "ManagingCPM": self.epv.cpm if cpm is None else cpm,
            "NumberOfVersionsRetention": self.epv.retention if versions is None else versions,
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
                await self.add_member(safe_name, user, profile)
            except CyberarkAPIException as err:
                if err.http_status == 409:
                    # Already exists
                    pass
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
        members = await self.epv.handle_request("get", url, filter_func=lambda x: x["value"])

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

    async def list(self, details=False):
        """
        List all safes
        :return: A list of safes names
        """
        # if user is username of PSMMaster this is going to crash with a weird mapping type error...
        try:
            params = {
                "limit": 250
            }
            ret = await self.epv.handle_request("get", "api/Safes", params=params, filter_func=lambda r: r["value"])
        except CyberarkAPIException as err:
            ret = await self.epv.handle_request("get", 'WebServices/PIMServices.svc/Safes/',
                                                filter_func=lambda result: result["GetSafesSlashResult"])
        if details:
            return ret
        return [x["safeName"] for x in ret]


    async def get_permissions(self, safename: str, username: str):
        """
        Get a user (or group) permissions

        :param safename: Name of the safe
        :param username: Name of the user (or group)
        :return: list of permissions
        """
        url = f"api/Safes/{safename}/members/{username}"
        return await self.epv.handle_request("get", url, filter_func=lambda r: r["permissions"])
