Safe manipulation
========================
Safe related functions
--------------------------
add_member (in safe)
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_member(safe: str, username: str, profile: (str, dict))
    :async:
    :noindex:

    This functions adds the "username" user (or group) to the given safe with a relevant profile

    :param safe: The safe name
    :param username: the username or a group name
    :param profile: must be one of "admin", "use", "show", "audit", "prov", "power" or "cpm" (see also :ref:`Profiles`)
    :return: boolean

remove_member
~~~~~~~~~~~~~~~~~~
.. py:function:: remove_member(safe: str, username: str)
    :async:

    Remove a user or a group from a safe

    :param safe: The safe name
    :param username: The user or group name
    :return: Boolean

exists
~~~~~~~~
.. py:function:: exists(safename: str)
    :async:

    Return whether or not a safe exists

    :param safename: name of the safe
    :return: Boolean

add (safe)
~~~~~~~~~~~~~~~~
.. py:function:: add(safe_name: str, description="", location="", olac=False, days=-1, versions=None, auto_purge=False, cpm=None, add_admins=True)
    :async:

    Creates a new safe

    :param safe_name: The name of the safe to create
    :param description: The safe description
    :param location: Safe location (must be an existing location)
    :param olac: Enable OLAC for the safe (default to False)
    :param days: days of retention (if set, versions parameter is ignored)
    :param versions: number of versions (ignored if days => 0)
    :param auto_purge: Whether or not to automatically purge files after the end of the Object History Retention Period defined in the Safe properties.
    :param cpm: The name of the CPM user who will manage the new Safe.
    :param add_admins: Add "Vaults Admin" group and Administrator user as safe owners (Default to True)
    :return: boolean

add_defaults_admin
~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_defaults_admin(safe_name)
    :async:

    Add "Vaults Admin" group and Administrator user as safe owners

    :param safe_name: Name of the safe
    :return: boolean


delete (safe)
~~~~~~~~~~~~~~~~
.. py:function:: delete(safe_name)
    :async:
    :noindex:

    Delete the safe

    :param safe_name: Name of the safe
    :return: Boolean

list_members
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: list_members(self, safe_name: str, filter_perm=None, details=False, raw=False)
    :async:

    List members of a safe, optionally those with specific perm

    :param safe_name: Name of the safe
    :param filter_perm: A specific perm, for example "ManageSafe", see below
    :param details: If True, return a dict with more infos on each member
    :param raw: if True, return the API content directly (filter_perm and details are ignored)
    :return: list of all users, or list of users with specific perm

    List of valid perms are :

.. code-block::

    'useAccounts', 'retrieveAccounts', 'listAccounts', 'addAccounts', 'updateAccountContent',
    'updateAccountProperties', 'initiateCPMAccountManagementOperations',
    'specifyNextAccountContent', 'renameAccounts', 'deleteAccounts', 'unlockAccounts',
    'manageSafe', 'manageSafeMembers', 'backupSafe', 'viewAuditLog', 'viewSafeMembers',
    'accessWithoutConfirmation', 'createFolders', 'deleteFolders', 'moveAccountsAndFolders',
    'requestsAuthorizationLevel1', 'requestsAuthorizationLevel2'


is_member_of
~~~~~~~~~~~~~~~~~~
.. py:function:: is_member_of(safe_name: str, username: str)
    :async:

    Whether the user is member of the safe

    :param safe_name: Name of the safe
    :param username: Name of the user (or group)
    :return: boolean

list
~~~~~~~~~~
.. py:function:: list(details=False)
    :async:

    List all safes

    :return: A list of safes names

get_permissions
~~~~~~~~~~~~~~~~~~~
.. py:function:: get_permissions(safename: str, username: str)
    :async:

    Get a user (or group) permissions

    :param safename: Name of the safe
    :param username: Name of the user (or group)
    :return: list of permissions

Profiles
-----------
.. csv-table:: Profiles
    :header: "Profile name,", "Description"

    admin, All rights
    use, Minimal profile to perform a connect
    show, Connect + show password
    audit, Audit rights on safe
    prov, Add or delete objects on safe
    manager, Add or delete objects on safe and view + manage members
    power, connect + show + audit
    cpm, rights for a CPM users
