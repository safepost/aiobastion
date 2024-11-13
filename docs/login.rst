Login to the Vault
==================
aiobastion and CyberArk
-----------------------

.. _CyberArk Central Credential Provider - REST web service: https://docs.cyberark.com/AAM-CP/Latest/en/Content/CCP/Calling-the-Web-Service-using-REST.htm
.. _CyberArk Privileged Access Manager REST API: https://docs.cyberark.com/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm


There are 2 different CyberArk API used in **aiobastion**:

* Password Vault Web Access (refer in this documentation as *PVWA*)
    * The Password Vault Web Access (PVWA) enables both end users and administrators to access and manage privileged accounts from any local or remote location through a web client.
      This is the main reason why **aiobastion** has been made.

    * To use the interface you will need to set up a PWVA user in CyberArk (refer as the *PVWA user*).  This user will be allowed to access part or all the different components of CyberArk like

        * Manage account: Retrieve, list (search), add, update, rename, unlock, get secret (password), ...
        * Manage safe: Create, delete, update safe, safe members and backup safe
        * Monitor audit log and safe member
        * and more
    * Depending on your CyberArk security setup, you may not be able to access the **secret (password)** of an account with your *PVWA user*.
      This is where you may have to use the AIM interface.

For more information see `CyberArk Privileged Access Manager REST API`_ .

* Central Credential Provider web service (refer in this documentation as *AIM*)
    * The AIM API is the interface to get the secret (password) from one account at a time. The query has to return a unique account.
        * To use the interface you will need to set up an application user (applID) in CyberArk (refer as the *AIM user*) and for security reason **you must define a client certificate authentication to the AIM** (this is an aiobastion requirement).

For more information see `CyberArk Central Credential Provider - REST web service`_.

Connect to PVWA scenario
------------------------

There are several ways to login to the Vault:

* Using a configuration file (recommended approach)
* Using the serialization, information directly in your code (EPV *serialized* parameter)
* For partial initialization with a configuration file or with a serialization, you need to call one of the following:

    * `login function`_ to specify missing PVWA information like username, password, authentification method & PVWA user search information.
    * `login_with_aim function`_ to specify missing AIM information and the PVWA username, password, authentification method & PVWA user search information.



Connect with context manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Once *aiobastion.EPV* is set up, use the context manager to login and logoff automatically.

.. code-block:: python

    epv_env = aiobastion.EPV("/path/aiobastion_prod_config.yml")

    # Automatic login using configuration setup
    async with epv_env as epv:
        # do something, e.g.:
        print(await epv.safe.list())


Scenario #1 Login with a configuration file only (recommended approach)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is the easiest way to login the PVWA user.
Define all the information needed in the configuration file and you are ready to go.

* The configuration file has a *password* field in the *connection* section.  This way you don't need to use the AIM interface but be sure you're configuration file is in a secure place.
* For security reason, i would suggest configuring the AIM API.  It is longer but it's worth it.

See `Define a configuration file` for more information.

.. code-block:: python

    import aiobastion
    import asyncio

    async def main():
        epv_env = aiobastion.EPV("/path/aiobastion_prod_config.yml")

        async with epv_env as epv:
            # do something, e.g.:
            print(await epv.safe.list())

    if __name__ == '__main__':
        asyncio.run(main())


Scenario #2 Login with a configuration file and ask user and password
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Sometimes you need to ask the username and password in your code.

.. code-block:: python

    import aiobastion
    import asyncio
    import getpass

    async def initialize_pvwa():
        # Define login and password
        epv_env = aiobastion.EPV("/path/aiobastion_prod_config.yml")

        username = input("Enter CyberArk user: ")
        password = getpass.getpass("Enter CyberArk Password: ")

        # Login to the PVWA
        try:
            await epv_env.login(username=username, password=password)
        except GetTokenException as err:
            print(f"An error occured while login : {err}")
            await epv_env.close_session()
            raise

        return epv_env

    async def somework(epv):
        # For example, listing all safes
        safes = await epv.safe.list()
        for s in safes:
            print(s)

    async def main():
        epv_env = await initialize_pvwa()

        # Working with PVWA
        async with epv_env as epv:
            await somework(epv)

    if __name__ == '__main__':
        asyncio.run(main())


Scenario #3 Login with serialization with AIM & login function
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In this example, you don't need a configuration file.  You will get the *PVWA user* password using the AIM interface.

* First, define a python dictionary to initialize the interface for PVWA and AIM.
* Call the `login function`_ to login the *PVWA user*.

You can use the `Serialization tools`_ to extract the EPV serialization at any time after being set up.

.. code-block:: python

    import aiobastion
    import asyncio

    async def initialize_pvwa():
        # To use AIM serialization, you may specify the following information
        aim_config = {
            "appid":  "Automation_Application",         # (required) AIM Application ID
            "cert":   r"C:\Folder\AIM_Cert.pem",        # (required) AIM Filename public certificate
            "host":  "aim.mycompany.com",               # (required) AIM host
            "keep_cookies": False,                      # (optional) whether to keep cookies between calls, set to true if API host is behind a load balancer
            # "key":    r"C:\Folder\AIM_private_key",   # (required) AIM Filename Private Key certificate
            "max_concurrent_tasks": 10,                 # (optional) AIM Maximum number of parallel task (default 10)
            "passphrase":    "C3rtP4$$Phr4se",          # (optional) AIM certificate passphrase (password)
            "timeout": 30,                              # (optional) AIM Maximum wait time in seconds before generating a timeout (default 30 seconds)
            "verify": r"C:\Folder\AIM_Root_CA.pem"      # (optional) Directory or filename of the ROOT certificate authority (CA)
            }

        # Account definition (if needed)
        account_config = {
            "logon_account_index": 1,
            # "reconcile_account_index": 3
            }

        # Safe definition (if needed)
        safe_config = {
            "cpm": "PasswordManager",                   # (optional) CPM to assign to safes, default = "" (no CPM)
            "retention": 30                             # (optional) Days of retention for objects in safe, default = 10
            }

        # Global api options (if needed)
        api_options_config = {
            "deprecated_warning": False                 # (optional) Suppress deprecated warning, default = True (enable warning)
            }


        # PVWA serialization definition, you may specify the following information
        global_config = {
            "api_host": "pvwa.mycompany.com",           # (required) PVWA: hostname
            "authtype": "LDAP",                         # (optional) PVWA: Defaults is Cyberark. Acceptable values : Cyberark, Windows, LDAP or RADIUS
            "max_concurrent_tasks": 10,                 # (optional) PVWA: Maximum number of parallel task (default 10)
            "timeout": 30,                              # (optional) PVWA: Maximum wait time in seconds before generating a timeout (default 30 seconds)
            "verify": r"C:\Folder\PVWA_Root_CA.pem",    # (optional) PVWA: set if you want to add additional ROOT ca certs
            "keep_cookies": False,                      # (optional) PVWA: whether to keep cookies between calls, set to true if API host is behind a load balancer

            "aim": aim_config,                          # (optional) AIM     customization definition
            "account": account_config,                  # (optional) Account customization definition
            "safe": safe_config                         # (optional) Safe    customization definition
            "api_options": api_options_config           # (optional) Global api options
            }

        epv_env  = aiobastion.EPV(serialized=global_config)
        username = 'PVWAUSER001'

        # If PVWA username is unique
        pvwa_user_search = None

        # Or, if PVWA username is not unique, you must specify the user_search parameter.
        pvwa_user_search = {
            "safe":   "production_safe",
            "object": "Operating System-WinDomain-LDAP-PVWAUSER001"
            }

        try:
            await epv_env.login(username=username, user_search=pvwa_user_search)

        except GetTokenException as err:
            # handle failure here
            await epv_env.close_session()
            print(f"Unexpected error: {err}")
            raise

        return epv_env

    async def somework(epv):
        # For example, listing all safes
        safes = await epv.safe.list()
        for s in safes:
            print(s)

    async def main():
        epv_env = await initialize_pvwa()

        async with epv_env as epv:
            await somework(epv)

    if __name__ == '__main__':
        asyncio.run(main())


Scenario #4 Login with serialization with AIM & login_with_aim function
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In this example, you don't need a configuration file.  You will get the *PVWA user* password using the AIM interface.  We will use the login_with_aim to setup most AIM definition.

* First, define a python dictionary to initialize the interface for PVWA.
* Call the `login_with_AIM function`_ to login the *PVWA user*.
    * Most parameters are optional. If a parameter is not set, it will be obtained from *EPV* initialization.
    * Any specified parameter from the *login_with_aim* function will override the *EPV.AIM* definition.

You can use the `Serialization tools`_ to extract the EPV serialization at any time after being set up.

For demonstration purpose, AIM serialization is not define here. Otherwise refer to `Scenario #3 Login with serialization with AIM & login function`_

.. code-block:: python

    import aiobastion
    import asyncio

    async def initialize_pvwa():
        # For demonstration purpose, AIM serialization is not set here
        aim_config = None

        # PVWA serialization definition, you may specify the following information
        global_config = {
            "api_host": "pvwa.mycompany.com",           # (required) PVWA: Hostname
            "authtype": "LDAP",                         # (optional) PVWA: Defaults is Cyberark. Acceptable values : Cyberark, Windows, LDAP or RADIUS
            "max_concurrent_tasks": 10,                 # (optional) PVWA: Maximum number of parallel task (default 10)
            "timeout": 30,                              # (optional) PVWA: Maximum wait time in seconds before generating a timeout (default 30 seconds)
            "verify": true,                             # (optional) PVWA: set if you want to add additional ROOT ca certs
            "aim": aim_config
            }

        epv_env  = aiobastion.EPV(serialized=global_config)
        username = 'PVWAUSER001'

        # If PVWA username is unique
        pvwa_user_search = None

        # Or, If PVWA username is not unique, you must specify the user_search parameter.
        pvwa_user_search = {
            "safe":   "production_safe",
            "object": "Operating System-WinDomain-LDAP-PVWAUSER001"
            }

        try:
            await epv_env.login_with_aim(
                aim_host="aim.mycompany.com",
                appid="Automation_Application",
                cert_file=r"C:\Folder\AIM_Cert.pem",
                cert_key=r"C:\Folder\AIM_private_key",
                passphrase="C3rtP4$$Phr4se",
                verify=r"C:\Folder\AIM_Root_CA.pem",
                # timeout= 30,
                # max_concurrent_tasks= 10,
                # auth_type="cyberark",
                username=username,
                user_search=pvwa_user_search)
        except GetTokenException as err:
            # handle failure here
            await epv_env.close_session()
            print(f"Unexpected error: {err}")
            raise

        return epv_env

    async def somework(epv):
            # For example, listing all safes
            safes = await epv.safe.list()
            for s in safes:
                print(s)

    async def main():
        epv_env = await initialize_pvwa()

        # Working with PVWA
        async with epv_env as epv:
            await somework(epv)

    if __name__ == '__main__':
        asyncio.run(main())


Scenario #5 Login authentication with RADIUS account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you need to authenticate with RADIUS challenge / response mode, you need to catch the ChallengeResponseException and re-login with passcode :

.. code-block:: python

    import aiobastion
    import asyncio
    # import getpass

    async async def initialize_pvwa():
        pvwa_host = "pvwa.mycompany.com"
        authtype = "RADIUS"
        username = "PVWAUSER001"
        password = getpass.getpass()

        global_config = {'api_host': pvwa_host}

        epv_env  = aiobastion.EPV(serialized=global_config)

        try:
            await epv_env.login(username=username, password=password, auth_type=authtype)
        except ChallengeResponseException:
            passcode = input("Enter passcode: ")
            await epv_env.login(username=username, password=passcode, auth_type=authtype)

        except GetTokenException:
            # handle failure here
            await epv_env.close_session()
            raise

        return epv_env

    async def somework(epv):
        # For example, listing all safes
        safes = await epv.safe.list()
        for s in safes:
            print(s)

    async def main():
        epv_env = await initialize_pvwa()

        # Working with PVWA
        async with epv_env as epv:
            await somework(epv)

    if __name__ == '__main__':
        asyncio.run(main())


Connect to AIM only
-------------------
In rare cases, you may want to connect only with the AIM interface (without PVWA).

.. code-block:: python

    import aiobastion
    import asyncio

    def initialize_aim():
        # To use AIM serialization, you may specify the following information
        aim_config = {
            "appid":  "Automation_Application",         # (required) AIM Application ID
            "cert":   r"C:\Folder\AIM_Cert.pem",        # (required) AIM Filename public certificate
            "host":  "aim.mycompany.com",               # (required) AIM host
            "key":    r"C:\Folder\AIM_private_key",     # (required) AIM Filename Private Key certificate
            "max_concurrent_tasks": 13,                 # (optional) AIM Maximum number of parallel task (default 10)
            # "passphrase":    "C3rtP4$$Phr4se",        # (optional) AIM certificate passphrase (password)
            "timeout": 60,                              # (optional) AIM Maximum wait time in seconds before generating a timeout (default 30 seconds)
            "verify": True                              # (optional) Directory or filename of the ROOT certificate authority (CA)
            }

        aim_env  = aiobastion.aim.EPV_AIM(serialized=aim_config)

        return aim_env


    async def aim_somework(aim_env):
        try:
            # Extract secret (password) and account information in a dictionary
            # Return one and only one account
            username = "Administror"
            user_safe = "production-safe"

            secret_info = await aim_env.get_secret_detail(
                reason="Extract-utility.py; prepare safe migration",
                username=username,
                safe=user_safe)

            print("secret (password): ", secret_info.secret)
            print("detail: ", secret_info.detail)

        except aiobastion.exceptions.CyberarkAIMnotFound as err:
            print(f"Account {username} not found in safe {user_safe}: {err}")

        except (aiobastion.exceptions.CyberarkAPIException,
                aiobastion.exceptions.CyberarkException,
                aiobastion.exceptions.AiobastionException) as err:
            print(f"Unexcepted error: {str(err)}")
            raise


    async def main():
        aim_env = initialize_aim()

        # Working with AIM
        async with aim_env:
            await aim_somework(aim_env)

    if __name__ == '__main__':
        asyncio.run(main())


Define a configuration file
---------------------------
Defining a configuration file is the first step to allow you to connect to PVWA and start using this module.

All sections name and field attributes **are no longer case sensitive**.

The configuration file contains the following main sections:

+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| Section       | Type                  | Description                                                                                                          +
+===============+=======================+======================================================================================================================+
| account       | Optional              | account management customization field                                                                               +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| connection    | Required              | PVWA user login information.                                                                                         +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| pvwa          | Required              | PVWA Request management information.                                                                                 +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| aim           | Optional              | Specify the AIM Request management information (EPV.AIM).                                                            +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| api_options   | Optional              | Specify API global options.                                                                                          +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| cpm           | Optional, deprecated  | CPM user name managing the new safe.                                                                                 +
|               |                       |                                                                                                                      +
|               |                       | cpm has moved to the 'safe' section                                                                                  +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| custom        | Optional              | Customer section (EPV.config.custom).                                                                                +
|               |                       |                                                                                                                      +
|               |                       | This section is not used by aiobastion.                                                                              +
|               |                       |                                                                                                                      +
|               |                       | It is available to custom to add their own information if necessary.                                                 +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| label         | Optional              | Configuration name for information only (EPV.config.label).                                                          +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| retention     | Optional, deprecated  | For safe creation, the number of retained versions of every password that is stored in the Safe (EPV.retention).     +
|               |                       |                                                                                                                      +
|               |                       | retention has moved to the 'safe' section                                                                            +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+
| safe          | Optional              | Safe management customization field                                                                                  +
+---------------+-----------------------+----------------------------------------------------------------------------------------------------------------------+

CONNECTION section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+
| Field         | Type                    | Description                                                                                       +
+===============+=========================+===================================================================================================+
| applid        | Required if AIM is used | AIM Application ID                                                                                +
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+
| authtype      | Required                | logon authenticafication method (default Cyberark):                                               +
|               |                         |                                                                                                   +
|               |                         |  - Cyberark                                                                                       +
|               |                         |  - Windows                                                                                        +
|               |                         |  - LDAP                                                                                           +
|               |                         |  - RADIUS                                                                                         +
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+
| password      | Optional                | Password of the PVWA user.                                                                        +
|               |                         |                                                                                                   +
|               |                         | If AIM is not used or the field is not specified, you must call                                   +
|               |                         |                                                                                                   +
|               |                         | the `login function`_ or `login_with_aim function`_                                               +
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+
| username      | Optional                | PVWA user name.                                                                                   +
|               |                         |                                                                                                   +
|               |                         | If AIM is not used or the field is not specified, you must call                                   +
|               |                         |                                                                                                   +
|               |                         | the `login function`_ or `login_with_aim function`_                                               +
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+
| user_search   | Optional                | Search parameters to uniquely identify the PVWA user.                                             +
|               |                         |                                                                                                   +
|               |                         | For more information see `CyberArk Central Credential Provider - REST web service`_.              +
+---------------+-------------------------+---------------------------------------------------------------------------------------------------+

PVWA section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| Field                | Type                    | Description                                                                                +
+======================+=========================+============================================================================================+
| host                 | Required                | PVWA host name.                                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| timeout              | Optional                | PVWA Maximum wait time in seconds before generating a timeout (default 30 seconds).        +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| max_concurrent_tasks | Optional                | PVWA Maximum number of parallel task (default 10).                                         +
+----------------------+-------------------------+                                                                                            +
| maxtasks             | Optional, deprecated    +                                                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| verify               | Optional                | PVWA Directory or filename of the ROOT certificate authority (CA) (default False).         +
|                      |                         |                                                                                            +
|                      |                         | Possible value:                                                                            +
|                      |                         |                                                                                            +
|                      |                         |   -  False:         No SSL (not recommended)                                               +
|                      |                         |   -  True:          Use system SSL                                                         +
|                      |                         |   -  <directory>:   (capath) CA certificates to trust for certificate verification         +
|                      |                         |   -  <filename>:    (cafile) CA certificates to trust for certificate verification         +
+----------------------+-------------------------+                                                                                            +
| ca                   | Optional, deprecated    +                                                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| keep_cookies         | Optional                | Keep cookies from login and send in subsequent API calls (default False).                  +
|                      |                         | You may need to set to True when a load-balancer is present.                               +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+


AIM section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| Field                | Type                    | Description                                                                                +
+======================+=========================+============================================================================================+
| appid                | Required                | AIM host name. If not define use the *applid* from the CONNECTION section.                 +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| cert                 | Required                | AIM Filename public certificate                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| keep_cookies         | Optional                | Keep cookies from login and send in subsequent API calls (default False).                  +
|                      |                         | You may need to set to True when a load-balancer is present.                               +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| key                  | Required                | AIM Filename private key certificate                                                       +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| host                 | Required                | AIM CyberArk host name. If not define use the host from the PVWA section.                  +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| max_concurrent_tasks | Optional                | AIM Maximum number of parallel task (default 10).                                          +
|                      |                         |                                                                                            +
+----------------------+-------------------------+ If not define use the *max_concurrent_tasks* from the PVWA section.                        +
| maxtasks             | Optional, deprecated    +                                                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| passphrase           | Optional                | AIM private key certificate passphrase (password)                                          +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| timeout              | Optional                | AIM Maximum wait time in seconds before generating a timeout (default 30 seconds).         +
|                      |                         |                                                                                            +
|                      |                         | If not define use the *timeout* from the PVWA section.                                     +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| verify               | Optional                | PVWA Directory or filename of the ROOT certificate authority (CA) (default False).         +
|                      |                         |                                                                                            +
|                      |                         | Possible values:                                                                           +
|                      |                         |                                                                                            +
|                      |                         |   -  False:         No SSL (not recommended)                                               +
|                      |                         |   -  True:          Use system SSL                                                         +
|                      |                         |   -  <directory>:   (capath) CA certificates to trust for certificate verification         +
|                      |                         |   -  <filename>:    (cafile) CA certificates to trust for certificate verification         +
+----------------------+-------------------------+                                                                                            +
| ca                   | Optional, deprecated    +                                                                                            +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+


api_options section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+
| Field                | Type                    | Description                                                                                +
+======================+=========================+============================================================================================+
| deprecated_warning   | Optional                | Enable/disable deprecated warning (Defaut True)                                            +
|                      |                         |                                                                                            +
|                      |                         | Possible value:                                                                            +
|                      |                         |   -  False:         disable deprecated warning                                             +
|                      |                         |   -  True:          enable deprecated warning                                              +
+----------------------+-------------------------+--------------------------------------------------------------------------------------------+


ACCOUNT section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+
| Field                   | Type                    | Description                                                                                       +
+=========================+=========================+===================================================================================================+
| logon_account_index     | Optional                | The logon account index.                                                                          +
|                         |                         |                                                                                                   +
|                         |                         | The defaut value is 2 for compatibility.                                                          +
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+
| reconcile_account_index | Optional                | The reconcile account index.                                                                      +
|                         |                         |                                                                                                   +
|                         |                         | The default value 3 should NOT be changed unless your system has different custom value.          +
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+


SAFE section / field definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+
| Field                   | Type                    | Description                                                                                       +
+=========================+=========================+===================================================================================================+
| cpm                     | Optional                | CPM user name managing the new safe.                                                              +
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+
| retention               | Optional                | For safe creation, the number of retained versions of every password that is stored in the Safe.  +
+-------------------------+-------------------------+---------------------------------------------------------------------------------------------------+


A complete configuration file definition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: yaml

    label: Production Demo
    connection:
        username:   "PVWAUSER001"
        # password:   ""
        authtype:   "cyberark"
        user_search:
            object: "Operating System-WinDomain-LDAP-PVWAUSER001"
            safe:   "mysafe"
            folder: "Myfolder"
            address: "host_25"

    pvwa:
        host:                 "pvwa.mycompany.com"
        keep_cookies:         false
        max_concurrent_tasks: 12
        timeout:              45
        verify:               true

    aim:
        appid:                "appid_prod"
        host:                 "pvwa.acme.fr"
        cert:                 "C:\\Folder\\AIM_file.pem"
        # key:                "C:\\Folder\\AIM_file.key"
        passphrase:           "C3rtP4$$Phr4se"

        keep_cookies:         false
        verify:               "C:\\Folder\\Root_ca.crt"
        timeout:              45
        max_concurrent_tasks: 13

    account:
        logon_account_index:        1
        # reconcile_account_index:  3

    safe:
        cpm: "cpm_user"
        retention:  30

    api_options:
        deprecated_warning: true

    custom:
        custom1: "info 1"
        custom2: "info 2"


A minimal configuration file definition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A minimal file only defines a PVWA host.  You must call the `login function`_ or `login_with_aim function`_.

.. code-block:: yaml

    PVWA:
      Host: "pvwa.mycompany.com"


EPV Functions references
------------------------
.. currentmodule:: aiobastion.cyberark.EPV

Serialization tools
~~~~~~~~~~~~~~~~~~~
EPV objects can be serialized using "to_json" function, then deserialized using constructor.
This helps if you need to manage users session client side for example (token is kept in a cookie)
For security reasons, login and password are not stored in serialized object so you can't relogin after a timeout with a serialized object.
However, since your token is valid you can use it.

.. code-block:: python

    epv = EPV("/path/aiobastion_prod_config.yml)
    json_epv = epv.to_json()

    epv = EPV(serialized=json_epv)
    epv.do_something()


login function
~~~~~~~~~~~~~~
.. autofunction:: login

login_with_aim function
~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: login_with_aim

handle_request function
~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: handle_request
