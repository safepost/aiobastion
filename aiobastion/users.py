import asyncio
from .exceptions import AiobastionException, AiobastionConfigurationException

from typing import List


class User:
    # _USER_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        self.epv = epv
        self.user_list = None

        _section = "user"
        _config_source = self.epv.config.config_source

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}")

    def to_json(self):
        serialized = {}

        for attr_name in User._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized


    async def get_logged_on_user_details(self):
        """
        Returns information about the logged on user

        :return: dict with user information
        """
        url = "WebServices/PIMServices.svc/User"
        return await self.epv.handle_request("get", url)

    async def list(self, pattern: str = None, user_type: str = None, details=False, extended_details=False):
        """
        Returns a list of users matching criteria

        :param pattern: free search pattern
        :param user_type: user_type, for example "EPVUser"
        :param details: Instead of returning list of user names, return a list of dict with more infos
        :param extended_details: Adding groupsMembership, enableUser and suspended infos
        :return: A list of user, or a list of dict with extended details

        """
        data = {}

        if user_type is not None:
            data["userType"] = user_type

        if pattern is not None:
            data["search"] = pattern

        if extended_details:
            data["ExtendedDetails"] = str(extended_details)

        url = "api/Users"
        ret = await self.epv.handle_request("get", url, params=data, filter_func=lambda x: x["Users"])
        if details or extended_details:
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
        """
        Whether a user exists whose username is "username"
        :param username: username of the user
        :return: Boolean
        """
        if self.user_list is None:
            results = await self.epv.handle_request("get", 'API/Users', filter_func=lambda result: result["Users"])
            self.user_list = [u['username'].lower().strip() for u in results]
        return username.lower() in self.user_list

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
        :param username: username of the user - Required
        :param key_id: KeyID of the key to delete - Required
        :return: Boolean
        """
        url = f"WebServices/PIMServices.svc/Users/{username}/AuthenticationMethods/SSHKeyAuthentication" \
              f"/AuthorizedKeys/{key_id}"

        return await self.epv.handle_request("delete", url)

    async def del_all_ssh_keys(self, username: str):
        """
        Delete all SSH Keys of a given user
        :param username: Username of the user - Required
        :return: A list of booleans
        """
        keys = await self.get_ssh_keys(username)
        all_key_id = [k["KeyID"] for k in keys]
        tasks = [self.del_ssh_key(username, key) for key in all_key_id]
        return await asyncio.gather(*tasks)

    async def add(self, username: str, user_type: str = "EPVUser", non_authorized_interfaces: List = None,
                  location: str = "\\", expiry_date: int = None, enable_user: bool = True,
                  authentication_method: List = None, password: str = None,
                  change_password_on_the_next_logon: bool = True, password_never_expires: bool = False,
                  distinguished_name: str = None, vault_authorization: List = None, business_address: dict = None,
                  internet: dict = None, phones: dict = None, description: str = None, personal_details: dict = None
                  ):
        """
        Add a new user
        :param username: The name of the user - Required
        :param user_type: The user type that was returned according to the license. - Default: EPVUser
        :param non_authorized_interfaces: The CyberArk interfaces that this user is not authorized to use. - Default: None
        :param location: Location of the user - Default: \\
        :param expiry_date: The date when the user expires. (Date-type int) - Default: None
        :param enable_user: Whether the user will be enabled upon creation. - Default: True
        :param authentication_method: Restrict authentication method that the user will use to log on. - Default: None
        :param password: The password that the user will use to log on for the first time - Default: None - Not required for PKI or LDAP
        :param change_password_on_the_next_logon: Whether the user must change their password at first logon. - Default: False
        :param password_never_expires: Whether the user’s password will not expire unless they decide to change it. - Default: False
        :param distinguished_name: The user’s distinguished name for PKI auth.  - Default: None
        :param vault_authorization: The list of user permissions (refer to documentation) - Default : None
        :param business_address: The user's postal address dict (refer to documentation) - Default: None
        :param internet: The user's email dict (refer to documentation) - Default: None
        :param phones: The user's phones dict (refer to documentation) - Default: None
        :param description: Description free text - Default: None
        :param personal_details: The user's personal details dict (refer to documentation) - Default: None
        :return: A dict representation of the newly created user
        """
        #
        # if non_authorized_interfaces is None:
        #     non_authorized_interfaces = []

        new_user = {
            "username": username,
            "userType": user_type,
            "initialPassword": password,
            "authenticationMethod": authentication_method,
            "location": location,
            "unAuthorizedInterfaces": non_authorized_interfaces,
            "expiryDate": expiry_date,
            "vaultAuthorization": vault_authorization,
            "enableUser": str(enable_user),
            "changePassOnNextLogon": str(change_password_on_the_next_logon),
            "passwordNeverExpires": str(password_never_expires),
            "distinguishedName": distinguished_name,
            "description": description,
            "businessAddress": business_address,
            "internet": internet,
            "phones": phones,
            "personalDetails": personal_details
        }

        new_user_filtered = {k: v for k, v in new_user.items() if v is not None}

        return await self.epv.handle_request("post", f"API/Users/", data=new_user_filtered)

    async def delete(self, username: str):
        user_id = await self.get_id(username)
        return await self.epv.handle_request("delete", f"API/Users/{user_id}/")


    # TODO : Document me
    async def safes(self, username: str, user_id=None, details=False):
        """
        Returns the safes of a specific user

        :param username: the username
        :param user_id: the user_id if the username is not provided
        :return: user's safes list
        """
        if user_id is None:
            if username == "":
                raise AiobastionException("You must provide username or user_id")
            user_id = await self.get_id(username)
        url = f"api/Users/{user_id}/safes"
        if details:
            return await self.epv.handle_request("get", url, filter_func=lambda x: x["Safes"])
        else:
            safes = await self.epv.handle_request("get", url, filter_func=lambda x: x["Safes"])
            return [s["SafeName"] for s in safes]



class Group:
    # _GROUP_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        self.epv = epv

        _section = "group"
        _config_source = self.epv.config.config_source

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}")


    def to_json(self):
        serialized = {}

        for attr_name in Group._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

    async def list(self, pattern: str = None, group_type: str = None, details: bool = False,
                   include_members: bool = False):
        """

        :param pattern:
        :param group_type:
        :param details:
        :param include_members:
        :return:
        """
        url = f"api/UserGroups"
        params = {}

        if group_type is not None:
            params["filter"] = f"groupType eq {group_type}"
        if pattern is not None:
            params["search"] = pattern
        if include_members:
            params["includeMembers"] = "True"

        groups = await self.epv.handle_request("get", url, params=params, filter_func=lambda x: x["value"])
        if details or include_members:
            return groups
        else:
            return [g["groupName"] for g in groups]

    async def details(self, group_id, include_members: bool = False):
        """
        Get details about a specific group (PVWA v12.2 required)
        :param group_id: Unique ID of the group - Required
        :param include_members: Include members of the group - Default: False
        :return: Dict representation of the group
        """
        # > v12.2
        url = f"api/UserGroups/{group_id}"
        params = {}

        if include_members:
            params["includeMembers"] = "True"

        return await self.epv.handle_request("get", url, params=params)

    async def get_id(self, group_name: str):
        """
        Get Unique ID of a group with his name
        :param group_name: Name of the group
        :return: Unique ID of the group
        :raise: Aiobastion exception if group was not found
        """
        url = f"api/UserGroups"
        ret = await self.epv.handle_request("get", url, filter_func=lambda x: x["value"])
        for r in ret:
            if r['groupName'].upper() == group_name.upper():
                return r['id']
        raise AiobastionException(f"No such user found : {group_name}")

    async def add(self, name: str, description="", location='\\'):
        """
        Add the group in the Vault

        :param name: Name of the new group
        :param description: Description of the group
        :param location: Location of the group (defaults to \\)
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
            if r['groupName'].upper() == group_name.upper():
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
        return await self.epv.handle_request("post", f'api/UserGroups/{groupId}/Members', data=data)

    async def del_member(self, groupId: str, username: str):
        """
        Add the user or group identified by username on the group identified by groupId

        :param groupId: The unique ID of the group that is retrieved by get_id
        :param username: the user or group name to delete from the safe
        :return: Boolean
        """

        url = f'api/UserGroups/{groupId}/Members/{username}/'
        return await self.epv.handle_request("delete", url)
