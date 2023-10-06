
Login to the Vault
==================
There is several ways to login to the Vault:

* Using a configuration file (recommended approach)
    * Using a configuration file and a known login / password (or OTP) to perform login
    * Using a configuration file and get a login / password through AAM (or AIM)
* Defining all information directly in the code

Defining all information directly in the code
-------------------------------------------------
First define the dict with all the infos you want, then perform a login

.. code-block:: python

    api_config = {
        "api_host": "pvwa.mycompany.com", # (required) API host (eg the PVWA host)
        "authtype": "LDAP", # (optional) Defaults is Cyberark. Acceptable values : Cyberark, Windows, LDAP or Radius
        "max_concurrent_tasks": 10, # (optional) Defaults is 10
        "timeout": 30, #(seconds) (optional), timeout for requests to PVWA, default = 30
        "retention": 10, #(days) (optional), days of retention for objects in safe, default = 10
        "cpm": "PasswordManager", # (optional), CPM to assign to safes, default = "" (no CPM)
        "verify": "C:/Folder/PVWA_Root_CA.pem", # (optional), set if you want to add additional ca certs
        "AIM": { # (optional), serialization of AIM object, Defaults to None
            "host": "aim.mycompany.com", # (required if AIM is defined) AIM host
            "appid": "Automation_Application", # (required if AIM is defined) Your AppID
            "Cert": "C:/Folder/AIM_Cert.pem", # (required if AIM is defined) Certificate to authenticate with
            "Key": "C:/Folder/AIM_private_key", # (required if AIM is defined) Private Key of your cert
            "Verify": "C:/Folder/AIM_Root_CA.pem" # (optional) Define a specific CA cert for AIM
        },
    }

    vault = aiobastion.EPV(serialized = api_config)

    # Define login and password
    login = input("Login: ")
    password = input("Password: ")

    # Login to the PVWA
    try:
        await vault.login(login, password)
    except GetTokenException as err:
        print(f"An error occured while login : {err}")
        await vault.close_session()
        raise

    # Working with PVWA
    async with vault as epv:
        # For example, listing all safes
        safes = await epv.safe.list()
        for s in safes:
            print(s)

If you need to authenticate with RADIUS challenge / response mode, you need to catch the ChallengeResponseException and re-login with passcode :

.. code-block:: python

    pvwa_host = 'pam-host'
    authtype = 'Radius'
    username = 'username'
    password = getpass.getpass()

    config = {'api_host': pvwa_host}

    try:
        await vault.login(username, password, authtype)
    except ChallengeResponseException:
        passcode = input("Enter passcode: ")
        await vault.login(username, passcode, authtype)
    except GetTokenException:
        # handle failure here
        await vault.close_session()
        raise




Define a configuration file
----------------------------
Defining a configuration file is the first step to allow you to connect to PVWA and start using this module.

You have different choices in order to login:
 - :ref:`Specify a login / password that can perform API calls hardcoded in a config file <pvwa_login>`
 - :ref:`Use a minimal configuration file and specify the username and the password in your code<pvwa_login_nopasswd>`
 - :ref:`Use an account stored in the Vault that you will retrieve with AIM (AAM) using a certificate<aim_login>`


.. _pvwa_login:

Login with PVWA and specified login and password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: yaml

    Label: Production Vault
    Connection:
      Username: admin_restapi
      Password: sup3rs3cur3
      Authtype:
    PVWA:
      Host: "pvwa.acme.fr"
      CA: "C:/Folder/PVWA_Root_CA.pem"

.. _pvwa_login_nopasswd:

Login with PVWA and specify user or password later
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A minimal file only defines a PVWA host

.. code-block:: yaml

    PVWA:
      Host: "pvwa.acme.fr"

.. _aim_login:

Login with AIM
~~~~~~~~~~~~~~~~
Example file for connecting through AIM

.. code-block:: yaml

    Label: Production Vault
    Connection:
      Username: admin_restapi
    PVWA: 
      Host: "pvwa.acme.fr"
    AIM:
      Host: "aim.acme.fr"
      AppID: "Automation"
      Cert: "C:/Folder/cert.pem"
      Key: "C:/Folder/key.pem"

Lookup for a specific user to login with
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
By default when you use the the AIM to perform a logon through the PVWA, it will search for the username you specified in all your safes to retrieve the password.
If you have multiple username corresponding to it, it will fail forcing you to have unique username.

To achieve this, you can use the User_Search directive in configuration file inside the Connection section:

.. code-block:: yaml

    # None of those are mandatory, you can pick only one if it suits your needs, or combine multiple fields.
    Connection:
        Username: admin
        User_Search:
            Safe:   "mysafe"
            object: "Application-xxx_admin_rest_api-server1"
            Folder: "Myfolder"
            Address: "host_25"



Additional configuration options for AIM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: yaml

    timeout: 30 #(seconds) optional, timeout for requests to PVWA, default = 30
    retention: 10 #(days) optional, days of retention for objects in safe, default = 10
    CPM: "PasswordManager" #optional, CPM to assign to safes, default = "" (no CPM)
    CA: "C:/Folder/AIM_Root_CA.pem" #optional, set if you want to add additional ca certs

Full file sample
~~~~~~~~~~~~~~~~~~~~
.. code-block:: yaml

    Label: Demo Vault
    Connection:
        Username:
        Password:
        AuthType:
        User_Search:
            Object:
            Safe:
    PVWA:
        Host:
        Timeout:
        MaxTasks:
        Verify:
    AIM:
        Host:    "pvwa.acme.fr"  (Default PVWA: host)
        AppID:   "appid_prod"        (Default Connection: applid)
        Cert:    "C:\\Folder\\AIM_file.crt"
        key:     "C:\\Folder\\AIM_file.key"
        Verify:  "C:\\Folder\\PVWA_Root_ca.pem"  (Default PVWA: CA)
        timeout: 45       (Default PVWA: timeout)
        max_concurrent_tasks: 13  (Default PVWA: max_concurrent_tasks)

    CPM:
    Custom:
    retention:




Connect to the PVWA
---------------------

Connect with context manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once defined, use either context manager to login if you don't need to specify login / password

.. code-block:: python

    production_vault = aiobastion.EPV("../path/to/config")
        async with production_vault as epv:
            # do something, eg:
            print(await epv.safe.list())



Connect with login call
~~~~~~~~~~~~~~~~~~~~~~~~~~

Or if you need to explicitly login you can call the login function

.. note::

    The login function accept 3 arguments: username, password and authtype
    The authtype can be either Cyberark Windows Ldap or Radius


.. code-block:: python

    production_vault = aiobastion.EPV("../path/to/config")
    await production_vault.login("Administrator", "Cyberark1", "Cyberark")

    production_vault.login(
        async with production_vault as epv:
            # do something, eg:
            print(await epv.safe.list())


Logging with AIM call
~~~~~~~~~~~~~~~~~~~~~~~~
You can also login with AIM using the login_with_aim function if you chose to don't put the infos on the config file :

.. py:function:: login_with_aim(aim_host, appid, username, cert_file: str, cert_key: str, root_ca=False):
    :async:

We only support client certificate authentication to the AIM


A real life example
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    import aiobastion
    import asyncio

    async def main():
        production_vault = aiobastion.EPV("../confs/config_prod.yml")
        await production_vault.login("Administrator", "Cyberark1", "Cyberark")
        async with production_vault as epv:
            print(await epv.safe.list())

    if __name__ == '__main__':
        asyncio.run(main())


Serialization
-------------
EPV objects can be serialized using "to_json" function, then deserialized using constructor.
This helps if you need to manage users session client side for example (token is kept in a cookie)
For security reasons, login and password are not stored in serialized object so you can't relogin after a timeout with a serialized object.
However, since your token is valid you can use it.

.. code-block:: python

    epv = EPV("configfile")
    json_epv = epv.to_json()

    epv = EPV(serialized=json_epv)
    epv.do_something()
