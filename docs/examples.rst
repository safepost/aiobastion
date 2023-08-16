Account manipulation
=======================

Creating an accounts
------------------------

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


