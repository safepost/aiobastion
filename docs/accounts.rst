Accounts
==========================

In the following table, Account design a PrivilegedAccount object described below.

.. csv-table:: Section overview
    :header: "Section", "Description"

    `Finding accounts`_ , "Search and find accounts in the vault"
    `Creating accounts`_ , "Create accounts"
    `Account management`_ , "get, update, link, delete and move accounts"
    `Password Actions`_ , "Change, reconcile, verify, set or get passwords"
    `Password management`_ , "Disable or resume password management, get CPM Status"
    `Account Group membership`_ , "Add or remove account to an account group"
    `Miscellaneous`_, "Other account related function, connect, get ID, find FC path..."

The PrivilegedAccount Class
------------------------------
PrivilegedAccount is a Python class that represent a Cyberark Account to avoid dictionary manipulation in code.
Most of the following function works with objects of this class.
It was made the most generic possible, however you can completely customize it you way using inheritance.

It has the following mandatory attributes:
    * name: Cyberark name of the account (eg unixsrv01-dbadmin).
    * platformId: ID of the platform (eg UnixSSH).
    * safeName: The safe in which the account is stored (eg DBA-Safe).

It has the following extra attributes:
    * userName: Username of the account (eg dbadmin)
    * address: Address of the account (eg unixsev01)
    * id: Cyberark unique ID of the account (eg 12-451)
    * secret: The password of the account
    * secretManagement: A dictionary with the secret management infos
    * secretType: The type of password ("password" or "key")
    * platformAccountProperties: A dictionary with all optional file categories
    * remoteMachinesAccess: A dictionary with the remote machines access infos

it has the following methods :
    * get_name : return the computed name "address-username"
    * to_json: return a dict representation of the Object
    * cpm_status: return the CPM status of the account
    * last_modified : return the last modified time (days since last password change)

About linked account index :
    * reconcile account index: 3 - you should NOT change it unless your system has different custom value.
    * logon account index: 2 - this is different from the installation (1). The default value is kept at 2 to avoid
      breaking existing users. You can override it to 1 by providing a "accounts.LOGON_ACCOUNT_INDEX" value in your config.

Calling functions
-------------------
| When it's possible, functions support call with a list as argument instead of single item argument.
| You **should try to use list to have the maximum benefit from the async implementation**.
| The return of a function called with a list is a list of applied function **in the same order** the initial list was given.
| If an exception is raised for an item, the exception will be returned as a member of the list (and not raised directly).


Finding accounts
---------------------
.. currentmodule:: aiobastion.accounts.Account
.. autofunction:: search_account_by
.. autofunction:: search_account
.. autofunction:: search_account_iterator
.. autofunction:: search_account_paginate
.. autofunction:: search_account_by_ip_addr

Creating accounts
--------------------
.. autofunction:: add_account_to_safe

Account management
----------------------
.. autofunction:: update_file_category
.. autofunction:: update_platform
.. autofunction:: update_single_fc
.. autofunction:: update_using_list
.. autofunction:: move
.. autofunction:: link_account
.. autofunction:: link_logon_account
.. autofunction:: link_reconciliation_account
.. autofunction:: link_reconcile_account_by_address
.. autofunction:: unlink_account
.. autofunction:: remove_logon_account
.. autofunction:: remove_reconcile_account
.. autofunction:: delete


Password Actions
------------------
.. autofunction:: change_password
.. autofunction:: reconcile
.. autofunction:: verify
.. autofunction:: get_secret
.. autofunction:: get_password
.. autofunction:: get_password_aim
.. autofunction:: get_secret_aim
.. autofunction:: get_ssh_key
.. autofunction:: get_secret_versions
.. autofunction:: set_password
.. autofunction:: set_next_password
.. autofunction:: restore_last_cpm_version
.. autofunction:: restore_last_cpm_version_by_cpm



Password management
----------------------
.. autofunction:: disable_password_management
.. autofunction:: resume_password_management
.. autofunction:: get_cpm_status
.. autofunction:: activity
.. autofunction:: last_cpm_error_message



Account Group membership
---------------------------
.. autofunction:: get_account_group
.. autofunction:: add_member_to_group
.. autofunction:: del_account_group_membership


Miscellaneous
---------------
.. autofunction:: connect_using_PSM
.. autofunction:: detect_fc_path
.. autofunction:: get_account
.. autofunction:: get_account_id
.. autofunction:: is_valid_safename
.. autofunction:: is_valid_username


..
    for documenting a single function =>
    .. autofunction:: aiobastion.accounts.Account.handle_acc_id_list

    .. currentmodule:: aiobastion.accounts.Account
    .. autofunction:: link_account


    .. autoclass:: aiobastion.accounts.Account
    :members: set_next_password
