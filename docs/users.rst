User manipulation
======================
User related functions
---------------------------
get_logged_on_user_details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_logged_on_user_details():
    :async:

    Returns information about the logged on user

    :return: dict with user information

list (users)
~~~~~~~~~~~~~~~~
.. py:function:: list(pattern: str = None, user_type: str = None, details=False)
    :async:
    :noindex:

    Returns a list of users matching criteria

    :param pattern: free search pattern
    :param user_type: user_type, for example "EPVUser"
    :param details: Instead of returning list of user names, return a list of dict with all infos
    :return: A list of user, or a list of dict with extended details


get_id
~~~~~~~~~~~~
.. py:function:: get_id(username: str)
    :async:

    Get the unique ID of a user

    :param username: the username of the user
    :return: the ID (int)

exists (user)
~~~~~~~~~~~~~~~~
.. py:function:: exists(username: str)
    :async:
    :noindex:

    Return whether or not a user exists

    :param safename: name of the user
    :return: Boolean

details (user)
~~~~~~~~~~~~~~~~~~
.. py:function:: details(username: str = "", user_id=None)
    :async:
    :noindex:

    Get user details

    :param username: the username, if user_id is not provided
    :param user_id: the user_id if the username is not provided
    :return: Information about a user in the Vault

groups
~~~~~~~~~~
.. py:function:: groups(username)
    :async:

    Returns the groups of a specific user

    :param username: the username
    :return: user's groups list


add_ssh_key
~~~~~~~~~~~~~~~~
.. py:function:: add_ssh_key(username: str, key: str)
    :async:

    Add SSH key to user for authenticate with PSMP

    :param username: user that will use the key
    :param key: openssh public key (often starts with ssh-rsa and NOT --begin ssh2 etc.. which is putty format)
    :return: ID of the key and newly inserted key

get_ssh_keys
~~~~~~~~~~~~~~~~
.. py:function:: get_ssh_keys(username: str)
    :async:

    List all keys of a specific user

    :param username: username of the user
    :return: list of dict with user's keys (KeyID, PublicSSHKey)

del_ssh_key
~~~~~~~~~~~~~~
.. py:function:: del_ssh_key(username: str, key_id: str)
    :async:

    Deletes the key identified by key_id of the username

    :param username: username of the user
    :param key_id: KeyID of the key to delete
    :return: Boolean

del_all_ssh_keys
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: del_all_ssh_keys(username: str)
    :async:

    Deletes all the keys of the given user

    :param username: username of the user
    :return: Boolean

Group manipulation
========================
Group related functions
---------------------------

list (groups)
~~~~~~~~~~~~~~~~
.. py:function:: list(pattern: str = None, group_type: str = None)
    :async:
    :noindex:

    Returns a list of groups matching criteria

    :param pattern: free search pattern
    :param group_type: group type
    :return: A list of groups

get_id (group)
~~~~~~~~~~~~~~~~~~
.. py:function:: get_id(group_name: str)
    :async:
    :noindex:

    Get the unique ID of a group

    :param group_name: the username of the user
    :return: the ID (int)

add (group)
~~~~~~~~~~~~~~
.. py:function:: add(name: str)
    :async:
    :noindex:

    Add the group in the Vault

    :param name: Name of the new group
    :param description: Description of the group
    :param location: Location of the group (defaults to \ )
    :return: Boolean

delete (group)
~~~~~~~~~~~~~~~~
.. py:function:: delete(group_name: str)
    :async:
    :noindex:

    Delete the group identified by group_name

    :param group_name: Name of the group
    :return: Boolean

members (of a group)
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: members(group_name:str)
    :async:

    List the members of the group identified by group_name

    :param group_name: Name of the group
    :return: List of members

add_member (in group)
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_member(groupId: str, username: str, type="Vault", domain=None)
    :async:

    Add the user or group identified by username on the group identified by groupId

    :param groupId: The unique ID of the group that is retrieved by get_id
    :param username: the user or group name to add on the safe
    :param type: the user type (domain or vault), Vault by default
    :param domain: the DNS address of the domain, mandatory if type is domain
    :return: Boolean