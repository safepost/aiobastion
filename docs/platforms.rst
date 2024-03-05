Platforms
============================
Functions
------------------------------

.. currentmodule:: aiobastion.platforms.Platform
.. autofunction:: get_target_platforms
.. autofunction:: get_platforms_details
.. autofunction:: search_target_platform
.. autofunction:: get_target_platform_details
.. autofunction:: get_target_platform_unique_id
.. autofunction:: del_target_platform
.. autofunction:: deactivate_target_platform
.. autofunction:: export_platform
.. autofunction:: get_target_platform_connection_components
.. autofunction:: get_session_management_policy
.. autofunction:: export_all_platforms
.. autofunction:: import_connection_component


Return Examples
----------------------
get_platform_details example return
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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


get_platforms_details example return
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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


get_target_platform_details example return
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

get_session_management_policy example return
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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


Code samples
---------------------------
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
            print(f"{p};{len(r)}")

Export then delete a platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    async with prod as epv:

        pf_name = "PLATFORM_NAME"
        await epv.platform.export_platform(pf_name, "../../../saved_platforms/")
        pf_uid = await epv.platform.get_target_platform_unique_id(pf_name)
        await epv.platform.del_target_plaform(pf_uid)

Or something like this:

.. code-block:: python

        pf_name = ""

        while pf_name != "exit":
            pf_name = input("PF name: ")
            await epv.platform.export_platform(pf_name, "../../../saved_platforms/")
            pf_uid = await epv.platform.get_target_platform_unique_id(pf_name)
            await epv.platform.del_target_plaform(pf_uid)
            print(f"{pf_name} successfully deleted !")

