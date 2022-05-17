Account manipulation
==========================

In the following table, Account design a PrivilegedAccount object described below.

.. csv-table:: Section overview
    :header: "Section", "Description"

    :ref:`Updating accounts` , Search and find accounts in the vault
    :ref:`Creating accounts` , Create accounts
    :ref:`Account manipulation` , get, update, delete and move accounts
    :ref:`Password Actions` , Change, reconcile, verify, set or get passwords
    :ref:`Password management` , Disable or resume password management, get CPM Status


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
    * to_json: return the json representation of the Object
    * cpm_status: return the CPM status of the account

Calling functions
-------------------
| When it's possible, functions support call with a list as argument instead of single item argument.
| You **should try to use list to have the maximum benefit from the async implementation**.
| The return of a function called with a list is a list of applied function **in the same order** the initial list was given.
| If an exception is raised for an item, the exception will be returned as a member of the list (and not raised directly).

Finding Accounts
------------------

search_account_by
~~~~~~~~~~~~~~~~~~~~

.. py:function:: search_account_by(keywords, username, address, safe, platform, ip)
    :async:

    The easiest way to retrieve accounts from the vault is to use the search_account_by function.
    It allows you to either search on given keywords, or more precisely on a account attribute

    The supported attributes are :
     * keywords : will return all accounts that match .\*keyword.\*
     * username : will check if username of the account exists and if the content exact match the given value
     * address : will check if the address of the account exact matches the given value
     * safe : will filter on this safe name
     * platform : will check if the platformID exact matches the given value
     * anything_you_want : will check if this extra FC of your object exists and the content exact match the value

    This return a list of "PrivilegedAccount" objects.

    Note: This function doesn't populate the secret field (password), you have to make a separated call if you want to get it.

search_account_iterator
~~~~~~~~~~~~~~~~~~~~~~~~

.. py:function:: search_account_iterator(keywords, username, address, safe, platform, ip)
    :async:

    Instead of returning a list like previous function, this one returns an async interator

search_account_paginate
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:function:: search_account_paginate(page, size_of_page, safe, search, **kwargs)
    :async:

    This function returns a dictionary with :

.. code-block::

    {
        "has_next_page" : boolean,
        "accounts": list of PrivilegedAccount
    }

* page: The page number (starting at 1)
* size_of_page: the size of pages (max 1000)
* safe : the safe name, if wanted
* search : free search string
* any parameters = value : ensure that the file category "parameter" exact matches the string

See also "search_account_by" function

For your convenience you can use platform="PF-NAME" instead of platformID (and thus if you have a custom "platform" FC it will not be considered).

search_account_by_ip_addr
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: search_account_by_ip_addr(address)

    This function will search an account by IP address bu checking if "address" is a valid IPv4 address and checking if "Address" property of the account is exactly the given address.
    You can also provide an PrivilegedAccount, the function will search on its address property

    :param address: PrivilegedAccount or string (valid IPv4 address)
    :return: list(PrivilegedAccount)
    :raise TypeError: If address is not valid

search_account
~~~~~~~~~~~~~~~~~~
.. py:function:: search_account(expression)

    Free search (like in PVWA search bar)

    :param expression: string
    :return: list(PrivilegedAccount)

Creating accounts
------------------
add_account_to_safe
~~~~~~~~~~~~~~~~~~~~~

.. py:function:: add_account_to_safe(accounts)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function creates the PrivilegedAccount (or the list of PrivilegedAccount) in the account's safe (the safe attribute of the account).
    If the account(s) already exists, then raises a CyberarkAPIException

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: account_id or list(account_id | exceptions)
    :raise bastion.CyberarkAPIException: If there is something wrong


Updating accounts
-----------------------

get_account
~~~~~~~~~~~~~~~~

.. py:function:: get_account(account_id)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function returns a Privileged account object for a given account_id (or list of account_id)

    :param account_id: account_id or list(account_id)
    :return: PrivilegedAccount or list(PrivilegedAccount | exceptions)
    :raise bastion.CyberarkException: (404) if account don't exists


get_account_id
~~~~~~~~~~~~~~~~~~
.. py:function:: get_account_id(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function returns an account_id (or list) for a given PrivilegedAccount (or list of PrivilegedAccount) by searching it with username, address and safe.


    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: account_id or list(account_id)
    :raise bastion.CyberarkException: if no account found

connect_using_PSM
~~~~~~~~~~~~~~~~~~~~
.. py:function:: connect_using_PSM(account_id, connection_component)
    :async:

    This function returns a file content (bytes) which is the equivalent RDP file of the "Connect" button

    :param account: PrivilegedAccount or account_id
    :return: file_content
    :raise bastion.CyberarkAPIException: if an error occured

    Example use:

.. code-block::

        async with production_vault as epv:
            # find first active connexion component
            try:
                unique_id = await epv.platform.get_target_platform_unique_id(account.platformId)
                ccs = await epv.platform.get_target_platform_connection_components(unique_id)
                cc = None
                for _cc in ccs:
                    if _cc["Enabled"]:
                        cc = _cc["PSMConnectorID"]
                        break
            except CyberarkException as err:
                # You are not Vault Admin
                self.assertIn("PASWS041E", str(err))

            rdp_content = await epv.account.connect_using_PSM(account.id, cc)
            with open("connect_account.rdp", "w") as rdp_file:
                rdp_file.write(rdp_content)

update_platform
~~~~~~~~~~~~~~~~~~~~
.. py:function:: update_platform(account, new_platform_id)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function updates the account's (or list) plafrom

    :param account: PrivilegedAccount, list of Privileged Accounts
    :param new_plaform_id: The new plaform ID (eg Unix-SSH)
    :return: True if succeeded

update_using_list
~~~~~~~~~~~~~~~~~~~~
.. py:function:: update_using_list(account, data)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function updates an account (or list) with the data list of changes.
    For more infos, check Cyberark documentation. (see example below)

    :param account: PrivilegedAccount, list of Privileged Accounts or account_id or list
    :param data: a list of dictionaries
    :return: True if succeeded
    :raise bastion.CyberarkAPIException: if an error occured

Example usage :

.. code-block::

    # insert here logon to vault and retrieve an account

    data = [
            {"path": "/name", "op": "replace", "value": "new_name",
            {"path": "/address", "op": "replace", "value": "192.168.1.1"},
            {"path": "/platformId", "op": "replace", "value": "LINUX-SERVERS"},
            {"path": "/platformAccountProperties/Details", "op": "replace", "value": "Production Vault"},

    ]
    is_updated = epv.account.update_using_list(account, data)

delete
~~~~~~~~
.. py:function:: delete(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This deletes the account (or list).

    If this is an SSH Key, this function will delete it on the Vault but not on systems!

    :param account: PrivilegedAccount or list(PrivilegedAccount) to delete
    :return: True if succeeded
    :raise bastion.CyberarkException: if delete failed



add_member_to_group
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_member_to_group(account, group_name)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Adds the account, or list of accounts, to the "group_name" account group

    :param account: PrivilegedAccount, list of Privileged Accounts
    :param group_name: Name of the group
    :return: True, if succeeded

get_account_group
~~~~~~~~~~~~~~~~~~
.. py:function:: get_account_group(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Returns the Group ID of a given PrivilegedAccount (or list).

    To get the group name, and more, check the Account Group section of this documentation.

    :param account: PrivilegedAccount, list of Privileged Accounts
    :return: GroupID (which is not the group name)

del_account_group_membership
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_account_group_membership(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Find and delete the account_group membership of a PrivilegedAccount (or list)

    :param account: PrivilegedAccount, list of Privileged Accounts
    :return: Boolean

move
~~~~~~
.. py:function:: move(account, new_safe)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Delete the account (or list) and recreate it (or them) in with the same parameters and password in the new safe.

    :param account: PrivilegedAccount, list of Privileged Accounts
    :param new_safe: New safe to move the account(s) into
    :return: Boolean

Link accounts
---------------
link_reconciliation_account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: link_reconciliation_account(account, rec_account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function links the account (or the list of accounts) to the given reconcile account

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param rec_account: PrivilegedAccount
    :return: True
    :raise bastion.CyberarkException: if link failed

link_logon_account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: link_logon_account(account, logon_account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function links the account (or the list of accounts) to the given logon account

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param logon_account: PrivilegedAccount
    :return: True
    :raise bastion.CyberarkException: if link failed

link_reconcile_account_by_address
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: link_reconcile_account_by_address(account_username, rec_account_username, address)
    :async:

    This function links the account with the given username and address to the reconciliation account with the given rec_account_username and the given address

    :param account_username: username of the account to link
    :param rec_account_username: username of the reconciliation account
    :param address: address of both accounts
    :return: True
    :raise bastion.CyberarkException: if link failed

remove_reconcile_account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: remove_reconcile_account(account, rec_account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function unlinks the reconciliation account of the given account (or the list of accounts))

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: True
    :raise bastion.CyberarkException: if link failed

remove_logon_account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: remove_logon_account(account, rec_account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function unlinks the logon account of the given account (or the list of accounts))

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: True
    :raise bastion.CyberarkException: if link failed

Password Actions
---------------------
change_password
~~~~~~~~~~~~~~~~~~
.. py:function:: change_password(account, change_group=False)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function set the account (or list) for immediate change.

    Keep in mind that for list, exceptions are returned and not raised.

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param change_group: change entire group, default to False
    :return: True
    :raise bastion.CyberarkException: if link failed

reconcile
~~~~~~~~~~~~~
.. py:function:: reconcile(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function set the account (or list) for immediate reconciliation.

    Keep in mind that for list, exceptions are returned and not raised.

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: True
    :raise bastion.CyberarkException: if link failed

verify
~~~~~~~~~~~~~
.. py:function:: verify(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This function set the account (or list) for immediate verify.

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: True
    :raise bastion.CyberarkException: if link failed

get_password
~~~~~~~~~~~~~~~~~~
.. py:function:: get_password(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Retrieves the password of the account, or the list of accounts.

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :return: The password (or list of passwords)
    :raise bastion.CyberarkException: if retrieve failed

set_password
~~~~~~~~~~~~~~
.. py:function:: set_password(account, password)
    :async:

    :ref:`Support list as argument<Calling functions>`

    Changes the password of the account, or the list of accounts, **in the Vault**.

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param password: new password to set
    :return: The password (or list of passwords)
    :raise bastion.CyberarkException: if set password failed (your platform enforce complexity or you don't have rights)


Password management
--------------------
disable_password_management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: disable_password_management(account, reason)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This disables the account (or list) password management

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param reason: The reason of disabling password management (defaults to empty string)
    :return: True
    :raise bastion.CyberarkException: if link failed

resume_password_management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: resume_password_management(account, reason)
    :async:

    :ref:`Support list as argument<Calling functions>`

    This resumes the account (or list) password management

    :param account: PrivilegedAccount or list(PrivilegedAccount)
    :param reason: The reason of disabling password management (defaults to empty string)
    :return: True
    :raise bastion.CyberarkException: if link failed

get_cpm_status
~~~~~~~~~~~~~~~~~~
.. py:function:: get_cpm_status(account)
    :async:

    :ref:`Support list as argument<Calling functions>`

    The functions returns the CPM status of an account, or list of accounts

    :param account: PrivilegedAccount, list of Privileged Accounts or account_id or list
    :return: Boolean saying if the account is CPM managed