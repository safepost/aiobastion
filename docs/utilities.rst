Utilities
=====================

For your convenience we provide some "utility" function that are not directly an interface with the rest API but can be commonly use.

CPM Functions
--------------

cpm_change_failed_accounts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: cpm_change_failed_accounts(address, username_filter)
    :async:

    CPM Change for all "red" accounts associated with an address, with a possible filter on username.

    :param address: exact value of field Address in EPV
    :param username_filter: Put a list of username in filter to change only those accounts (default all accounts)


cpm_change
~~~~~~~~~~~~~~~~~~~
.. py:function:: cpm_change_failed_accounts(address, username_filter)
    :async:

    CPM Change for all accounts associated with an address, with a possible filter on username.

    :param address: exact value of field Address in EPV.
    :param username_filter: Put a list of username in filter to change only those accounts (default all accounts)

manual_set_password
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: manual_set_password(address, username_filter)
    :async:

    Set a password in the Vault for all accounts associated with an address, with a possible filter on username.

    :param address: exact value of field Address in EPV
    :param password: New password to put on the address
    :param username_filter: Which accounts to put the password on (list)


reconcile_failed_accounts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: reconcile_failed_accounts(address, username_filter)
    :async:

    CPM Reconcile for all "red" accounts associated with an address, with a possible filter on username.

    :param address: exact value of field Address in EPV
    :param username_filter: Put a list of username in filter to reconcile only those accounts (default all accounts)

reconcile
~~~~~~~~~~~~~~~~~~~
.. py:function:: reconcile(address, username_filter)
    :async:

   Reconcile all accounts associated with an address, with a possible filter on username.

   :param address: exact value of field Address in EPV.
   :param username_filter: Put a list of username in filter to reconcile only those accounts (default all accounts)

account_status
~~~~~~~~~~~~~~~~~~~~
.. py:function:: account_status(address: str, accounts: list)

    Give the CPM status of accounts for an address

    :param address: Exact match of address field
    :param accounts: List of accounts to get the status for
    :return: A string with True and the number of good accounts found, or False with list of failed accounts

Platform manipulation
------------------------

migrate_platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: migrate_platform(old_platform: str, new_platform: str, address_filter: list = None)
    :async:

    Migrate all accounts from old platform to new platform, with a possible selection of address

    :param old_platform: Platform to migrate from
    :param new_platform: Platform to migrate to
    :param address_filter: A list of address (exact value of field address) to migrate (default ALL address)


Account manipulation
------------------------

delete_accounts
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: delete_accounts(address: str, safe_pattern_filter: str = "")
    :async:

    Delete all accounts associated to an address, with a possible filter on safe you want to ignore.

    :param safe_pattern_filter: Safe pattern you want to IGNORE
    :param address: address file category exact match

clone_address
~~~~~~~~~~~~~~~~~~
.. py:function:: clone_address(address: str, replace: dict, update_name=True):
    :async:

    Find all accounts associated with an address, then clone it with new parameters.

    :param address: Address of accounts to clone
    :param replace: FC to replace : ex {"address": "new_address", "safeName": "new_safe"}
    :param update_name: automatic update of the address name, True by default
    :return: Boolean telling if the accounts were created

clone_account
~~~~~~~~~~~~~~~~~~
.. py:function:: clone_account(address: str, username: str, replace: dict, update_name=True)
    :async:

    Find all accounts associated with an address, then clone it with new parameters.

    :param address: Address of account to clone
    :param username: Username of account to clone
    :param replace: dict with replace ex {"address": "new_address", "safeName": "new_safe"}
    :param update_name: automatic update of the name
    :return: Boolean telling if the account was created

Tasks manipulation
---------------------
gather_with_concurrency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:function:: gather_with_concurrency(n, *tasks, return_exceptions=False):
    :async:

    Gather a list of coroutines with concurrency

    :param n: Number of max corountines launched at the same time (semaphore)
    :param tasks: task1, task2, ..., tasksn (if you have a list then prefix it with *)
    :param return_exceptions: if set to True, exceptions are returned as regular results, instead of being raised
    :return: List of results in the same order as the tasks

stack_with_concurrency
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: stack_with_concurrency(list_of_address:list, function, max_tasks=10, return_exceptions=False, **args)
    :async:


    Quickly apply concurrently a function to a list of address

    :param list_of_address: list of address to apply the function on
    :param function: the function
    :param max_tasks: max concurrent tasks
    :param return_exception: whether the function will return Exception as normal return, or raise
    :param args: dict of args of the function
    :return: list of return in the order of adresses
