Getting Started
=================

Introduction
---------------
What you have to do:
 * Install this package and all the requirements
 * Create a configuration file to connect to your Vault
 * Manipulate your accounts with the asynchronous logic (see examples below)

Examples
-----------
Here's few examples that show you how to use this package.
Put these examples in a function, and run it with asyncio.run:

.. code-block:: python

    async def example():
        # code taken from an example below

    if __name__ == "__main__":
        asyncio.run(example())

Example 1: Find all red accounts in a particular safe and verify them
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: python

    production = bastion.EPV("path/to/config.yml")
    async with production as vault:
        # Returns a list of all accounts in the safe
        safe_account = await vault.account.search_account_by(safe="dba-admin-safe")

        # Apply a filter to find the red accounts
        red_accounts = [ accounts for accounts in safe_account if not account.cpm_status() ]

        # Perform the verify on all those accounts
        await vault.account.verify(red_accounts)


Example 2 : Link all account named "root" to a Logon account "admin"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: python

    production = bastion.EPV("path/to/config.yml")
    async with production as vault:
        # Returns a list of all root accounts in the safe
        root_accounts = await vault.account.search_account_by(safe="linux-safe", username="root")

        # Get the logon accounts in two different safes
        admin_accounts = await vault.accout.search_account_by(safe="primary-safe", username="admin")
        admin_accounts.extend(await vault.accout.search_account_by(safe="other-safe", username="admin"))

        # Apply a filter to find the red accounts
        for r in root_accounts:
            # we search the admin_accounts where the address is equivalent
            for a in admin_accounts:
                if r.address == a.address:
                    await vault.account.link_logon_account(r, a)
                    break
            else:
                print(f"No logon account found for account with address : {r.address}")


This can be optimized by creating a list of tasks "link_logon_account" and gather it in the end.

Tips
______

When working with accounts you will sometimes loop on hostnames and want to find associated accounts.
In this case, the best approach is to first dump all the safe in a list and then find your accounts in the returned list.

If you make one search by account, you will lower the performances by far.

In addition, when you have to perform several tasks, first create a list of tasks, then run it.

Do this :
.. code-block:: python

    production = bastion.EPV("path/to/config.yml")
    async with production as vault:
        # Dump all safe in a list of account
        admin_accounts = await vault.account.search_account_by(safe="Admins-Accounts-Safe")

        # Initiate an empty task list
        tasks_list = []
        for host in host_list:
            # find the corresponding account in the list with address equivalent to host, or None
            current_host_account = next((h for h in admin_accounts if h.address.lower() == host.lower()), None)
            if current_host_account in not None:
                # Add the wanted action to the task list, here a cpm_change
                tasks_list.append(vault.account.change(current_host_account))

        # Run the tasks_list with a PVWA semaphore of size 10, returning exception as normal result (don't stop on error)
        print(await vault.utils.gather_with_concurrency(10, *tasks_list, return_exceptions=True))


Don't do this :

.. code-block:: python

    production = bastion.EPV("path/to/config.yml")
    async with production as vault:
        # Dump all safe in a list of account
        admin_accounts = await vault.account.search_account_by(safe="Admins-Accounts-Safe")

        # Initiate an empty task list
        tasks_list = []
        for host in host_list:
            # works, but makes one request to the PVWA for each account instead of one for all accounts
            current_host_account = await vault.account.search_account_by(safe="Admins-Accounts-Safe", address=host)

            # Works, but immediately execute the change blocking the script execution instead of using concurrency
            try:
                print(await vault.account.change(current_host_account))
            except Exception as err:
                print(f"An error as occured when changing {host}'s password")
