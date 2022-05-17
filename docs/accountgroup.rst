Account Group Manipulation
=============================
The PrivilegedAccountGroup Class
-------------------------------------
PrivilegedAccountGroup is a Python class that represent a Cyberark Account Group to avoid dictionary manipulation in code.
Most of the following function works with objects of this class.

It has the following mandatory attributes:
    * name: Cyberark name of the account group ("sample_group_name")
    * group_platform: The group platform (eg "sample_group_platform")
    * safeName: The safe in which the account is stored (eg DBA-Safe).

It has the following extra attributes:
    * id: Cyberark unique ID of the account group (eg 43_391)

Functions
-----------
list_by_safe
~~~~~~~~~~~~~~
.. py:function:: list_by_safe(safe_name)
    :async:

    Returns the list of PrivilegedAccountGroup for a given safe

    :param safe: the safe name
    :return: list(PrivilegedAccountGroup)

members
~~~~~~~~~~
.. py:function:: members(group)
    :async:
    :noindex:


    Returns the list of members (PrivilegedAccount) for a given PrivilegedAccountGroup

    :param group: PrivilegedAccountGroup
    :return: list(PrivilegedAccountGroup)

add
~~~~~~~~~~
.. py:function:: add(group_name, group_platform, safe_name)
    :async:
    :noindex:

    Creates the Privileged Account Group with parameters in the Vault

    :param group_name: group name
    :param group_platform: group platform
    :param safe_name: safe name
    :return: group unique id

add_privileged_account_group
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_privileged_account_group(account_group)
    :async:

    Creates the Privileged Account Group in the Vault from the object

    :param account_group: A PrivilegedAccountGroup object
    :return: group unique id

add_member
~~~~~~~~~~~~
.. py:function:: add_member(account, group)
    :async:
    :noindex:

    Adds the given Privileged Account to the group

    :param account: A PrivilegedAccount object
    :param group: A PrivilegedAccountGroup object
    :return: Boolean

delete_member
~~~~~~~~~~~~~~~~~~
.. py:function:: delete_member(account, group)
    :async:

    Delete the given Privileged Account from the group

    :param account: A PrivilegedAccount object
    :param group: A PrivilegedAccountGroup object
    :return: Boolean



get_privileged_account_group_id
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_privileged_account_group_id(account_group)
    :async:

    Returns the unique ID of the PrivilegedAccountGroup.

    For this to work, the safe and name attributes must be relevant.

    :param account_group: a PrivilegedAccountGroup
    :return: The account group ID

