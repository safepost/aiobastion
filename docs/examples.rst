Examples
============

Account manipulation
-------------------------

Creating accounts
~~~~~~~~~~~~~~~~~~~~~~~~

To create an account, simply create a "PrivilegedAccount" object and then add it to a safe.

.. code-block:: python

    async with vault as epv:

        db_admin_account = PrivilegedAccount(
                    name="unixsrv01-dbadmin",
                    userName="dbadmin",
                    address="unixsrv01",
                    safeName="db_safe_01",
                    platformId="UnixSSH",
                    secret="reconcileme",
                    platformAccountProperties={
                        "CustomFC1": "MariaDB",
                        "CustomFC2": "Billing",
                    },
                )

        try:
            acc_id = await epv.account.add_account_to_safe(db_admin_account)
            print(f"Account {acc_id} was successfully created")
        except CyberarkAPIException as err:
            print(f"An error as occured while trying to add account in safe : {str(err)}")


Resume password management accounts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    async with vault as epv:
        admin_unix_accounts = await epv.account.search_account_by(platform="UnixSSH", username="admin")
        await epv.account.resume_password_management(admin_unix_accounts)