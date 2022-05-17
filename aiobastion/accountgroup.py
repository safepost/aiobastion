import re

from .accounts import PrivilegedAccount
from .abstract import Vault
from .exceptions import AiobastionException


class PrivilegedAccountGroup:
    def __init__(self, GroupName: str, GroupPlatformID: str, Safe: str, GroupID: str= ""):
        self.id = GroupID
        self.name = GroupName
        self.group_platform = GroupPlatformID
        self.safe = Safe

    # ready to add json representation
    def to_json(self):
        json_object = {
            "GroupName": self.name,
            "GroupPlatformID": self.group_platform,
            "Safe": self.safe
        }
        return json_object

    def __str__(self):
        return f"id : {self.id}, name: {self.name}, group_platform: {self.group_platform}, safe: {self.safe}"



class AccountGroup:
    def __init__(self, epv: Vault):
        self.epv = epv

    # Account groups
    async def list_by_safe(self, safe_name: str):
        """
        List all groups for a given safe
        :param safe_name: name of the safe
        :return: a list of PrivilegedAccountGroups
        """
        params = {
            "Safe": safe_name
        }
        groups = await self.epv.handle_request("get", "api/AccountGroups", params=params)
        return [PrivilegedAccountGroup(**g) for g in groups]

    async def get_privileged_account_group_id(self, account_group: PrivilegedAccountGroup):
        if account_group.id == "":
            acc = await self.list_by_safe(account_group.safe)
            for a in acc:
                if a.name == account_group.name:
                    return a.id
            raise AiobastionException(f"No ID found for group {account_group.name}")
        else:
            return account_group.id

    async def get_group_id(self, account_group):
        if type(account_group) is str:
            if re.match(r'\d+_\d+', account_group) is not None:
                return account_group
            else:
                raise AiobastionException("The account_group_id provided is not correct")
        if isinstance(account_group, PrivilegedAccountGroup):
            return await self.get_privileged_account_group_id(account_group)
        else:
            raise AiobastionException("You must provide a valid PrivilegedAccount to function get_account_id")

    async def members(self, group):
        group_id = await self.get_group_id(group)
        members = await self.epv.handle_request("get", f"api/AccountGroups/{group_id}/Members")
        return await self.epv.account.get_account([m["AccountID"] for m in members])

    async def add(self, group_name: str, group_platform: str, safe_name: str):
        """
        Add a privileged address group using group name, group platform and safe name
        :param group_name: group name
        :param group_platform: group platform
        :param safe_name: safe name
        :return: group id
        """
        if not await self.epv.safe.exists(safe_name):
            raise AiobastionException(f"Safe {safe_name} does not exists")
        data = {
            "GroupName": group_name,
            "GroupPlatformID": group_platform,
            "Safe": safe_name
        }
        return await self.epv.handle_request("post", "api/AccountGroups/", data=data, filter_func=lambda x: x['GroupID'])

    async def add_privileged_account_group(self, account_group: PrivilegedAccountGroup):
        """
        Add a privileged account group using a Privileged Account Group object
        @param account_group: a PrivilegedAccountGroup object
        @return: group id
        """
        if not await self.epv.safe.exists(account_group.safe):
            raise AiobastionException(f"Safe {account_group.safe} does not exists")
        return await self.epv.handle_request("post", "api/AccountGroups", data=account_group.to_json(),
                                             filter_func=lambda x: x['GroupID'])

    async def add_member(self, account: (PrivilegedAccount, str), group: (PrivilegedAccountGroup, str)):
        account_id = await self.epv.account.get_account_id(account)
        group_id = await self.get_group_id(group)
        data = {
            "AccountID": account_id
        }
        return await self.epv.handle_request("post", f"api/AccountGroups/{group_id}/Members", data=data)

    async def delete_member(self, account: (PrivilegedAccount, str), group: (PrivilegedAccountGroup, str)):
        group_id = await self.get_group_id(group)
        account_id = await self.epv.account.get_account_id(account)
        url = f"API/AccountGroups/{group_id}/Members/{account_id}"
        return await self.epv.handle_request("delete", url)

    # This API call does not exists
    # async def delete(self, group_id):
    #     if re.match(r'\d+_\d+', group_id) is None:
    #         raise BastionException("The provided Group ID is not valid !")
    #     return await self.epv.handle_request("delete", f"api/AccountGroups/{group_id}")
