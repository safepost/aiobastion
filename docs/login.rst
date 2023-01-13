
Login to the Vault
==================
Define a configuration file
----------------------------
Defining a configuration file is the first step to allow you to connect to PVWA and start using this module.

You have different choices in order to login:
 - :ref:`Specify a login / password that can perform API calls hardcoded in a config file<Login with PVWA and specified login and password>`
 - :ref:`Use a minimal configuration file and specify the username and the password in your code<Login with PVWA and specify user or password later>`
 - :ref:`Use an account stored in the Vault that you will retrieve with AIM (AAM) using a certificate<Login with AIM>`


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

Login with PVWA and specify user or password later
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A minimal file only defines a PVWA host

.. code-block:: yaml

    PVWA:
      Host: "pvwa.acme.fr"


Login with AIM
~~~~~~~~~~~~~~~~
Example file for connecting through AIM

.. code-block:: yaml

    Label: Production Vault
    Connection:
      Username: admin_restapi
    PVWA: "pvwa.acme.fr"
    AIM:
      Host: "aim.acme.fr"
      AppID: "Automation"
      Cert: "C:/Folder/cert.pem"
      Key: "C:/Folder/key.pem"
    #  CA: "C:/Folder/AIM_Root_CA.pem"
    CAFile: "C:/Folder/PVWA_Root_CA.pem"

Additional configuration options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: yaml

    timeout: 30 #(seconds) optional, timeout for requests to PVWA, default = 30
    retention: 10 #(days) optional, days of retention for objects in safe, default = 10
    CPM: "PasswordManager" #optional, CPM to assign to safes, default = "" (no CPM)

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
