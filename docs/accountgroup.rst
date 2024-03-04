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
.. currentmodule:: aiobastion.accountgroup.AccountGroup
.. autofunction:: list_by_safe
.. autofunction:: get_account_group_id
.. autofunction:: members
.. autofunction:: add
.. autofunction:: add_privileged_account_group
.. autofunction:: add_member
.. autofunction:: delete_member
.. autofunction:: move_account_group
.. autofunction:: move_all_account_groups
