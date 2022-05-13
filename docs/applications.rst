Application
=============

This section documents the function linked to application.

Functions
-----------
details
~~~~~~~~~~
.. py:function:: details(app_name)
    :async:

    Returns information about an application

    :param app_name: the application name
    :return: dictionary with application information

Example return :
.. code-block::

{'AccessPermittedFrom': 0, 'AccessPermittedTo': 24, 'AllowExtendedAuthenticationRestrictions': False, 'AppID': 'TestApp', 'BusinessOwnerEmail': '', 'BusinessOwnerFName': '', 'BusinessOwnerLName': '', 'BusinessOwnerPhone': '', 'Description': 'test App for testing bastion package', 'Disabled': False, 'ExpirationDate': None, 'Location': '\\'}

search
~~~~~~~~~~
.. py:function:: search(search)
    :async:

    Search applications by name

    :param search: free text to search application
    :return: list of application names

add_authentication
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: add_authentication(app_name: str, path: str = None, hash_string: str = None, os_user: str = None, address: str = None, serial_number: str = None, issuer: list = None, subject: list = None, subject_alternative_name: list = None, is_folder: bool = False, allow_internal_scripts: bool = False, comment: str = "") -> bool:
    :async:

    Add one or more authentication methods to a given app_id with a named param

    :param app_name: the name of the application
    :param path: path to authenticated
    :param hash_string: hash of script / binary
    :param os_user: os user that is running the script / binary
    :param address: IP address
    :param serial_number: certificate serial number
    :param issuer: list of certificate issuer (PVWA >= 11.4)
    :param subject: list of certificate subject (PVWA >= 11.4)
    :param subject_alternative_name: list of certificate SAN (eg ["DNS Name=www.example.com","IP Address=1.2.3.4"])
    :param allow_internal_scripts: relevant for path authentication only (False by default)
    :param is_folder: relevant for path authentication only (False by default)
    :param comment: relevant for hash and certificate serial number
    :return: boolean telling whether the application was updated or not

get_authentication
~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_authentication(self, app_name: str) -> list or bool
    :async:

    Get authenticated methods for an application

    :param app_name: The name of the application
    :return: a list of authentication methods

del_authentication
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: del_authentication(self, app_name: str, auth_id: str) -> list or bool:
    :async:

    Delete authentication method identified by auth_id for the application

    :param app_name: name of the application
    :param auth_id: retrieved with the get_authentication function
    :return: a boolean