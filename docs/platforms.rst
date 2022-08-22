Platforms manipulation
============================
Platform related functions
------------------------------

get_target_platforms
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_target_platforms(active: bool = None, systemType: str = None, periodicVerify: bool = None, manualVerify: bool = None, periodicChange: bool = None, manualChange: bool = None, automaticReconcile: bool = None, manualReconcile: bool = None)
    :async:

    Get target platforms that meet given criteria (or all platforms without argument)

    :param active: Boolean
    :param systemType: str
    :param periodicVerify: Boolean
    :param manualVerify: Boolean
    :param periodicChange: Boolean
    :param manualChange: Boolean
    :param automaticReconcile: Boolean
    :param manualReconcile: Boolean
    :return: List of target platform dictionaries

Example of a target platform dictionary :
.. code-block::

    {
       "Active":true,
       "SystemType":"Database",
       "AllowedSafes":".*",
       "PrivilegedAccessWorkflows":{
          "RequireDualControlPasswordAccessApproval":{
             "IsActive":false,
             "IsAnException":false
          },
          "EnforceCheckinCheckoutExclusiveAccess":{
             "IsActive":false,
             "IsAnException":false
          },
          "EnforceOnetimePasswordAccess":{
             "IsActive":false,
             "IsAnException":false
          },
          "RequireUsersToSpecifyReasonForAccess":{
             "IsActive":false,
             "IsAnException":false
          }
       },
       "CredentialsManagementPolicy":{
          "Verification":{
             "PerformAutomatic":false,
             "RequirePasswordEveryXDays":7,
             "AutoOnAdd":false,
             "AllowManual":true
          },
          "Change":{
             "PerformAutomatic":false,
             "RequirePasswordEveryXDays":90,
             "AutoOnAdd":false,
             "AllowManual":true
          },
          "Reconcile":{
             "AutomaticReconcileWhenUnsynced":false,
             "AllowManual":true
          },
          "SecretUpdateConfiguration":{
             "ChangePasswordInResetMode":false
          }
       },
       "ID":8,
       "PlatformID":"Oracle",
       "Name":"Oracle Database"
    }


get_platforms_details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_platforms_details(platform_name: str)
    :async:

        Get details for a given platform name

        :param platform_name: Platform name
        :return: a dictionary with the details of the platform

Example return:
.. code-block::

    {
       "PlatformID":"MySQL",
       "Details":{
          "PolicyID":"MySQL",
          "PolicyName":"MySQL Server",
          "PolicyType":"regular",
          "ImmediateInterval":"5",
          "Interval":"1440",
          "MaxConcurrentConnections":"3",
          "AllowedSafes":".*",
          "MinValidityPeriod":"60",
          "ResetOveridesMinValidity":"yes",
          "ResetOveridesTimeFrame":"yes",
          "Timeout":"30",
          "UnlockIfFail":"no",
          "UnrecoverableErrors":"5001,5002,5003,5004,5005,5006,2117",
          "MaximumRetries":"5",
          "MinDelayBetweenRetries":"90",
          "DllName":"PMODBC.dll",
          "XMLFile":"yes",
          "AllowManualChange":"Yes",
          "PerformPeriodicChange":"No",
          "HeadStartInterval":"5",
          "FromHour":"-1",
          "ToHour":"-1",
          "ChangeNotificationPeriod":"-1",
          "DaysNotifyPriorExpiration":"7",
          "VFAllowManualVerification":"Yes",
          "VFPerformPeriodicVerification":"No",
          "VFFromHour":"-1",
          "VFToHour":"-1",
          "RCAllowManualReconciliation":"Yes",
          "RCAutomaticReconcileWhenUnsynched":"No",
          "RCReconcileReasons":"2114,2115,2106,2101",
          "RCFromHour":"-1",
          "RCToHour":"-1",
          "NFNotifyPriorExpiration":"No",
          "NFPriorExpirationRecipients":"",
          "NFNotifyOnPasswordDisable":"Yes",
          "NFOnPasswordDisableRecipients":"",
          "NFNotifyOnVerificationErrors":"Yes",
          "NFOnVerificationErrorsRecipients":"",
          "NFNotifyOnPasswordUsed":"No",
          "NFOnPasswordUsedRecipients":"",
          "PasswordLength":"12",
          "MinUpperCase":"2",
          "MinLowerCase":"2",
          "MinDigit":"1",
          "MinSpecial":"-1",
          "PasswordForbiddenChars":"$\\'\\/@\".;{}()-|*>~!^#",
          "ChangeCommand":"Set password = '%NEWPASSWORD%'",
          "ReconcileCommand":"Set password for '%USER%' = '%NEWPASSWORD%'",
          "ConnectionCommand":"Driver={MySQL ODBC 5.3 Unicode Driver}",
          "Port":"3306",
          "Err2114":"N1045",
          "CommandForbiddenCharacters":"\\'\\/@\".{}() -;|*>~!^#\t;Characters that cannot be used in the parameters of the change/reconcile command.",
          "CommandBlackList":"delete,drop,exec,create,alter,rename,truncate,comment,select,insert,update,merge,call,explain,lock,grant,revoke",
          "OneTimePassword":"Non",
          "ExpirationPeriod":"90",
          "VFVerificationPeriod":"7",
          "PasswordLevelRequestTimeframe":"Non"
       },
       "Active":false
    }

search_target_platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: search_target_platform(self, search: str = "")
    :async:

        Free search on target platforms.
        Beware that for a search it can return several platforms
        If you want to search on a particular platform better use get_target_platform_details

        :param search: free search
        :return: a list of found platforms

get_target_platform_details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_target_platform_details(self, platform_name: str):
    :async:

        Give detail about one particular platform

        :param platform_name: Name of the platform
        :return: a dict with details of the platform

.. code-block::

    {
       "Active":true,
       "SystemType":"*NIX",
       "AllowedSafes":".*",
       "PrivilegedAccessWorkflows":{
          "RequireDualControlPasswordAccessApproval":{
             "IsActive":false,
             "IsAnException":false
          },
          "EnforceCheckinCheckoutExclusiveAccess":{
             "IsActive":true,
             "IsAnException":false
          },
          "EnforceOnetimePasswordAccess":{
             "IsActive":false,
             "IsAnException":false
          },
          "RequireUsersToSpecifyReasonForAccess":{
             "IsActive":false,
             "IsAnException":false
          }
       },
       "CredentialsManagementPolicy":{
          "Verification":{
             "PerformAutomatic":false,
             "RequirePasswordEveryXDays":7,
             "AutoOnAdd":false,
             "AllowManual":true
          },
          "Change":{
             "PerformAutomatic":false,
             "RequirePasswordEveryXDays":90,
             "AutoOnAdd":false,
             "AllowManual":true
          },
          "Reconcile":{
             "AutomaticReconcileWhenUnsynced":false,
             "AllowManual":true
          },
          "SecretUpdateConfiguration":{
             "ChangePasswordInResetMode":false
          }
       },
       "PrivilegedSessionManagement":{
          "PSMServerId":"PSMServer",
          "PSMServerName":"PSM"
       },
       "ID":38,
       "PlatformID":"LinuxDomainAccount",
       "Name":"Linux Domain Account"
    }

del_target_plaform
~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: del_target_plaform(pfid)
    :async:

    Delete target platform using ID
    You can get ID using :ref:`get_target_platform_details`

    :param pfid: Target Platform ID (eg 38)
    :return: Boolean

export_platform
~~~~~~~~~~~~~~~~~~~~
.. py:function:: export_platform(pfid: str, outdir: str)
    :async:

    Export platform files to outdir (existing directory)

    :param pfid: The platform ID (eg "Oracle")
    :param outdir: An existing directory on filesystem
    :return: Populate the dir with the files, and returns True

export_all_platforms
~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: export_all_platforms(outdir: str)
    :async:

    Export all platforms files to outdir (existing directory)

    :param outdir: An existing directory on filesystem
    :return: Populate the dir with the files, and returns True

get_target_platform_unique_id
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_target_platform_unique_id(platformID: str)
    :async:

    Retrieve the base64 ID of a platform

    :param platformID: the ID of platform (eg : WinDesktopLocal) or the name (eg "Oracle Database")
    :return: base64 ID of the platform


get_target_platform_connection_components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_target_platform_connection_components(platformId)
    :async:

    Get the list of PSMConnectors for a platform unique ID

    :param platformId: the base64 ID of platform (use :ref:`get_target_platform_unique_id`)
    :return: a list of connection component


get_session_management_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: get_session_management_policy(platformId)
    :async:

    Get management policy info for a platform

    :param platformId: The base64 UD of platform (use get_target_platform_unique_id)
    :return: a dict with management policy infos

.. code-block::

    {
       "PSMConnectors":[
          {
             "PSMConnectorID":"PSM-RDP",
             "Enabled":true
          },
          {
             "PSMConnectorID":"RDP",
             "Enabled":true
          },
          {
             "PSMConnectorID":"RDPWinApplet",
             "Enabled":true
          },
          {
             "PSMConnectorID":"RDPapplet",
             "Enabled":true
          }
       ],
       "PSMServerId":"PSMServer"
    }

import_connection_component
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. py:function:: import_connection_component(zipfile: str)
    :async:

    Import connection component

    :param zipfile: Contains the connection component info (or generated with cyberark tool)
    :return: True

Platform utilities functions
--------------------------------
Display the number of accounts by platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

        async with prod as epv:

        pfs = [h['Name'] for h in await epv.platform.get_target_platforms()]
        tasks = []
        for p in pfs:
            tasks.append(epv.account.search_account_by(platform=p))

        res = await asyncio.gather(*tasks)

        for p,r in zip(pfs,res):
            print(f"{p};{r}")