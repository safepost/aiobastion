import asyncio
from .abstract import Vault
from .exceptions import AiobastionException


class User:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def get_logged_on_user_details(self):
        """
        Returns information about the logged on user

        :return: dict with user information
        """
        url = "WebServices/PIMServices.svc/User"
        return await self.epv.handle_request("get", url)

    async def list(self, pattern: str = None, user_type: str = None, details=False):
        """
        Returns a list of users matching criteria

        :param pattern: free search pattern
        :param user_type: user_type, for example "EPVUser"
        :param details: Instead of returning list of user names, return a list of dict with all infos
        :return: A list of user, or a list of dict with extended details
        """
        data = {}

        if user_type is not None:
            data["userType"] = user_type

        if pattern is not None:
            data["search"] = pattern

        if details:
            data["ExtendedDetails"] = "True"

        url = "api/Users"
        ret = await self.epv.handle_request("get", url, params=data, filter_func=lambda x: x["Users"])
        if details:
            return ret
        else:
            return [u["username"] for u in ret]

    async def get_id(self, username: str):
        """
        get ID of a user

        :param username: the username of the user
        :return: the ID (int)
        """
        url = "api/Users"
        ret = await self.epv.handle_request("get", url, filter_func=lambda x: x["Users"])
        for r in ret:
            if r['username'] == username:
                return r['id']
        raise AiobastionException(f"No such user found : {username}")

    async def exists(self, username: str):
        if self.epv.user_list is None:
            results = await self.epv.handle_request("get", 'API/Users', filter_func=lambda result: result["Users"])
            self.epv.user_list = [u['username'].lower().strip() for u in results]
        return username in self.epv.user_list

    async def details(self, username: str = "", user_id=None):
        """
        Get user details

        :param username: the username, if user_id is not provided
        :param user_id: the user_id if the username is not provided
        :return: Information about a user in the Vault
        """
        if user_id is None:
            if username == "":
                raise AiobastionException("You must provide username or user_id")
            user_id = await self.get_id(username)
        url = f"api/Users/{user_id}"
        return await self.epv.handle_request("get", url)

    async def groups(self, username):
        """
        Returns the groups of a specific user

        :param username: the username
        :return: user's groups list
        """
        req = await self.details(username)
        return [g["groupName"] for g in req["groupsMembership"]]

    async def add_ssh_key(self, username: str, key: str):
        """
        Add SSH key to user for authenticate with PSMP
        :param username: user that will use the key
        :param key: openssh public key (often starts with ssh-rsa and NOT --begin ssh2 etc.. which is putty format)
        :return: ID of the key and newly inserted key
        """
        url = f"WebServices/PIMServices.svc/Users/{username}/AuthenticationMethods/SSHKeyAuthentication/AuthorizedKeys"

        key = {
            "PublicSSHKey": key.replace("\n", "")
        }

        return await self.epv.handle_request("post", url, data=key,
                                             filter_func=lambda r: r["AddUserAuthorizedKeyResult"])

    async def get_ssh_keys(self, username: str):
        """
        List all keys of a specific user

        :param username: username of the user
        :return: list of dict with user's keys (KeyID, PublicSSHKey)
        """
        url = f"WebServices/PIMServices.svc/Users/{username}/AuthenticationMethods/SSHKeyAuthentication/AuthorizedKeys"
        return await self.epv.handle_request("get", url, filter_func=lambda x: x["GetUserAuthorizedKeysResult"])

    async def del_ssh_key(self, username: str, key_id: str):
        """
        Deletes the key identified by key_id of the username

        :param username: username of the user
        :param key_id: KeyID of the key to delete
        :return: Boolean
        """
        url = f"WebServices/PIMServices.svc/Users/{username}/AuthenticationMethods/SSHKeyAuthentication" \
              f"/AuthorizedKeys/{key_id}"

        return await self.epv.handle_request("delete", url)

    async def del_all_ssh_keys(self, username: str):
        keys = await self.get_ssh_keys(username)
        all_key_id = [k["KeyID"] for k in keys]
        coros = []
        for key in all_key_id:
            coros.append(self.del_ssh_key(username, key))
        await asyncio.gather(*coros)


class Group:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def list(self, pattern: str = None, group_type: str = None):
        url = f"api/UserGroups"
        payload = {}

        if group_type is not None:
            payload["filter"] = f"groupType eq {group_type}"
        if pattern is not None:
            payload["search"] = pattern

        groups = await self.epv.handle_request("get", url, params=payload, filter_func=lambda x: x["value"])
        return [g["groupName"] for g in groups]

    async def get_id(self, group_name: str):
        url = f"api/UserGroups"
        ret = await self.epv.handle_request("get", url, filter_func=lambda x: x["value"])
        for r in ret:
            if r['groupName'] == group_name:
                return r['id']
        raise AiobastionException(f"No such user found : {group_name}")

    async def add(self, name: str, description="", location='\\'):
        """
        Add the group in the Vault

        :param name: Name of the new group
        :param description: Description of the group
        :param location: Location of the group (defaults to \ )
        :return: Boolean
        """
        group = {
            'groupName': name,
            'description': description,
            'location': location
        }

        return await self.epv.handle_request('post', 'api/UserGroups', data=group)

    async def delete(self, group_name: str):
        """
        Delete the group identified by group_name

        :param group_name: Name of the group
        :return: Boolean
        """
        group_id = await self.get_id(group_name)
        url = f"api/UserGroups/{group_id}"
        return await self.epv.handle_request("delete", url)

    async def members(self, group_name: str):
        """
        List the members of the group identified by group_name

        :param group_name: Name of the group
        :return: List of members
        """
        url = f"api/UserGroups"
        params = {"includeMembers": "True",
                  "filter": f"groupName eq {group_name}"}
        ret = await self.epv.handle_request("get", url, params=params, filter_func=lambda x: x["value"])
        for r in ret:
            if r['groupName'] == group_name:
                return r['members']
        raise AiobastionException(f"No such user found : {group_name}")

    async def add_member(self, groupId: str, username: str, type="Vault", domain=None):
        """
        Add the user or group identified by username on the group identified by groupId

        :param groupId: The unique ID of the group that is retrieved by get_id
        :param username: the user or group name to add on the safe
        :param type: the user type (domain or vault), Vault by default
        :param domain: the DNS address of the domain, mandatory if type is domain
        :return: Boolean
        """
        data = {
            'memberId': username,
            'memberType': type,
        }
        if domain is not None:
            data['domainName'] = domain
        return await self.epv.handle_request("post", f'api/UserGroups/{groupId})/Members', data=data)

