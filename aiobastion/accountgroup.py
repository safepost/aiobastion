import re
from typing import Union, List

from .accounts import PrivilegedAccount
from aiobastion.exceptions import AiobastionException, CyberarkAPIException, AiobastionConfigurationException, CyberarkNotFoundException


class PrivilegedAccountGroup:
    def __init__(self, GroupName: str, GroupPlatformID: str, Safe: str, GroupID: str= ""):
        self.id = GroupID
        self.name = GroupName
        self.group_platform = GroupPlatformID
        self.safe = Safe

    # ready to add json representation
    def to_json(self) -> dict:
        json_object = {
            "GroupName": self.name,
            "GroupPlatformID": self.group_platform,
            "Safe": self.safe
        }
        return json_object

    def __str__(self) -> str:
        return f"id : {self.id}, name: {self.name}, group_platform: {self.group_platform}, safe: {self.safe}"



class AccountGroup:
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        """
        AccountGroup   Account group management
        """
        self.epv = epv
        _section = "accountgroup"
        _config_source = self.epv.config.config_source

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(
                f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}"
            )

    def to_json(self) -> dict:
        return {attr_name: getattr(self, attr_name) for attr_name in AccountGroup._SERIALIZED_FIELDS if getattr(self, attr_name, None) is not None}


    # Account groups
    async def list_by_safe(self, safe_name: str) -> List[PrivilegedAccountGroup]:
        """
        List all groups for a given safe

        :param safe_name: name of the safe
        :return: a list of PrivilegedAccountGroups
        """
        params = {"Safe": safe_name}
        groups = await self.epv.handle_request("get", "api/AccountGroups", params=params)
        return [PrivilegedAccountGroup(**g) for g in groups]

    async def get_privileged_account_group_id(self, account_group: PrivilegedAccountGroup) -> str:
        """
        Internal function to get the group ID in functions

        :param account_group: PrivilegedAccountGroup object
        :return: group ID
        """
        if not account_group.id:
            acc = await self.list_by_safe(account_group.safe)
            for a in acc:
                if a.name == account_group.name:
                    return a.id
            raise AiobastionException(f"No ID found for group {account_group.name}")
        return account_group.id

    async def get_account_group_id(self, group_name: str, safe: str) -> str:
        """
        Get account_group_id with the group_name and the safe

        :param group_name: the name of the group
        :param safe: The name of the safe
        :return: The group ID
        """
        ais = await self.list_by_safe(safe)
        for _a in ais:
            if _a.name.lower() == group_name.lower():
                return _a.id
        raise AiobastionException(f"Group {group_name} not found in {safe}")

    async def get_group_id(self, account_group) -> str:
        """
        Internal function to get group_id from object or from group_id

        :param account_group: PrivilegedAccountGroup object or group_id
        :return: group_id
        """
        if isinstance(account_group, str):
            if re.match(r'\d+_\d+', account_group):
                return account_group
            raise AiobastionException("The account_group_id provided is not correct")
        if isinstance(account_group, PrivilegedAccountGroup):
            return await self.get_privileged_account_group_id(account_group)
        raise AiobastionException("You must provide a valid PrivilegedAccount to function get_account_id")

    async def members(self, group):
        """
        Returns the list of members (PrivilegedAccount) for a given PrivilegedAccountGroup

        :param group: PrivilegedAccountGroup or group_id
        :return: List of members of a group
        """
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
        self.epv.logger.debug(data)
        return await self.epv.handle_request("post", "api/AccountGroups/", data=data, filter_func=lambda x: x['GroupID'])

    async def add_privileged_account_group(self, account_group: PrivilegedAccountGroup):
        """
        Add a privileged account group using a Privileged Account Group object

        :param account_group: a PrivilegedAccountGroup object
        :return: group id
        """
        if not await self.epv.safe.exists(account_group.safe):
            raise AiobastionException(f"Safe {account_group.safe} does not exists")
        try:
            await self.epv.handle_request("post", "api/AccountGroups", data=account_group.to_json(),
                                             filter_func=lambda x: x['GroupID'])
        except CyberarkNotFoundException as err:
            raise CyberarkNotFoundException(f"Privileged Account group's platform \"{account_group.group_platform}\" not found")

    async def add_member(self, account: Union[PrivilegedAccount, str], group: Union[PrivilegedAccountGroup, str]):
        """
        Add accounts to a group (specified by PrivilegedAccountGroup object or group_id)

        :param account: PrivilegedAccount or account_id
        :param group:  PrivilegedAccountGroup or group_id (get it with
        :return: dict with {'AccountID' : 'acc_id'}
        :raises: CyberarkAPIException with err.http_status == 400 if account was already in a group
        """
        account_id = await self.epv.account.get_account_id(account)
        group_id = await self.get_group_id(group)
        data = {
            "AccountID": account_id
        }
        return await self.epv.handle_request("post", f"api/AccountGroups/{group_id}/Members", data=data)

    async def delete_member(self, account: Union[PrivilegedAccount, str], group: Union[PrivilegedAccountGroup, str]):
        """
        Delete the member of an account group

        :param account: PrivilegedAccount or account_id
        :param group: PrivilegedAccountGroup or privileged_account_id
        :return: Boolean
        """
        group_id = await self.get_group_id(group)
        account_id = await self.epv.account.get_account_id(account)
        url = f"API/AccountGroups/{group_id}/Members/{account_id}"
        return await self.epv.handle_request("delete", url)

    # This API call does not exist
    # async def get_account_group_details(self, group_id):
    #     url = f"API/AccountGroups/{group_id}"
    #     return await self.epv.handle_request("get", url)

    # This API call does not exist
    # async def delete(self, group_id):
    #     if re.match(r'\d+_\d+', group_id) is None:
    #         raise BastionException("The provided Group ID is not valid !")
    #     return await self.epv.handle_request("delete", f"api/AccountGroups/{group_id}")

    async def move_account_group(self, account_group_name: str, src_safe: str, dst_safe: str):
        """
        Move an account_group and its members from a safe to another safe

        :param account_group_name:
        :param src_safe:
        :param dst_safe: Where to store the account group
        :return: the new account group ID, or False if no group was found
        """
        account_groups = await self.list_by_safe(src_safe)
        for account_group in account_groups:
            if account_group.name.lower() == account_group_name.lower():

                try:
                    self.epv.logger.debug(f"Creating {account_group} to {dst_safe}")
                    new_group_id = await self.add(account_group.name, account_group.group_platform, dst_safe)
                    self.epv.logger.debug(f"Newly created group ID : {new_group_id}")

                except CyberarkAPIException as err:
                    if "EPVPA012E" in err.err_message:
                        ng_list = await self.list_by_safe(dst_safe)
                        new_group_id = next(ng for ng in ng_list if account_group.name.lower() == ng.name.lower())
                        self.epv.logger.debug(f"Warning : AG already exists and detected with ID : {new_group_id}")
                    else:
                        raise

                ag_members = await self.epv.accountgroup.members(account_group)
                # Moving accounts
                try:
                    moved_accounts = await self.epv.account.move(ag_members, dst_safe)
                except CyberarkAPIException as err:
                    raise

                self.epv.logger.debug("Accounts moved !")

                for agm in moved_accounts:
                    try:
                        await self.add_member(agm, new_group_id)
                        self.epv.logger.debug(f"Moved {agm} into {new_group_id}")
                    except:
                        # Account are moved with their account group
                        pass

                return new_group_id
        return False

    async def move_all_account_groups(self, src_safe, dst_safe, account_filter: dict = None):
        """
        Move all accounts groups from a safe to another safe
        * Members of the account groups are also moved ! *

        :param src_safe: Source safe
        :param dst_safe: Destination safe
        :param account_filter: filter : filter on accounts base file category, for example : {"platformId": "Unix-SSH"}
        """

        def _case_insensitive_getattr(obj, attr):
            for _a in dir(obj):
                if _a.lower() == attr.lower():
                    return getattr(obj, _a)

        account_groups = await self.list_by_safe(src_safe)
        for ag in account_groups:
            self.epv.logger.debug(f"Current AG is {ag}")
            ag_members = (await self.members(ag))
            self.epv.logger.debug(ag_members)
            if account_filter is not None:
                filtered = False
                for a in ag_members:
                    for filter_file_category, filter_value in account_filter.items():
                        try:
                            if _case_insensitive_getattr(a, filter_file_category) == filter_value:
                                filtered = True
                        except Exception as err:
                            # Most likely the filtered file category is not a basic one
                            raise AiobastionException(f"Your filter doesn't exist on account {a} "
                                                      f"(bad file category ? {filter_file_category})")
                if filtered:
                    self.epv.logger.debug("Account group skipped ....")
                    continue

            try:
                await self.move_account_group(ag.name, ag.safe, dst_safe)
            except CyberarkAPIException as err:
                raise
