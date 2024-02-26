# Contributing

<!-- TOC -->
* [Contributing](#contributing)
  * [How to contribute](#how-to-contribute)
  * [Bugs and issues](#bugs-and-issues)
  * [Code contribution](#code-contribution)
  * [Test](#test)
    * [Prepare CyberArk to Run the Testing](#prepare-cyberark-to-run-the-testing)
      * [Test Accounts and Permissions](#test-accounts-and-permissions)
      * [Platforms and Apps](#platforms-and-apps)
    * [Troubleshoot Test Issues](#troubleshoot-test-issues)
  * [Update documentation](#update-documentation)
<!-- TOC -->
## How to contribute

Any kind of contribution is welcomed. Because this project is quite new the best way to contribute right now is to start to use this module and give feedback about it.
 

## Bugs and issues

If ou find an error, a bug or an issue, feel free to [log an issue][new-issue]

## Code contribution

If you wish to contribute with code the workflow is :
- Clone the Github repo
- Make any change
- Make sure [all tests are passed](#test)
- [Update documentation](#updating-documentation)
- Submit a pull request the dev branch

## Test

- In order to test you need a working Vault and a PVWA.
- Then, generate some accounts with mockaroo and the following schemas : https://www.mockaroo.com/b41fedb0. See "Troubleshoot"
  section of some cleanup to avoid issues.
- Create the associated safes : sample-it-dept,sample-iaadmins,sample-coolteam
- Create safe "RENAME_ME", and grant user "admin_bot" (see below) to the "Safe Management" permissions (for safe
  rename testing)
- Import the data (with bulk upload)
- Create the configuration file for your testing Vault
- Check the \_\_init__.py file for the location of this file
- Ensure all tests are passed (or skipped)

### Prepare CyberArk to Run the Testing
#### Test Accounts and Permissions
You need an API user, such as **"admin_bot"**, to run the testing. This account is similar to Administrator for
permissions, but you can't use "Administrator" itself (you will get "PASWS291E You cannot perform this
task with an Administrator user. Log on with a different user and try again" error)
* In Private Ark Client:
  * Add to "Vault Admins" and "PVWAUsers" groups
  * Give "Add Safes, Audit Users, Add/Update Users, Reset Users' Passwords, Activate Users" authorizations rules.
  * Add to "admins" group (not sure this is needed)
  * Add as safe owners for the 3 test safes under user -> "Safe Ownership"
* In PVWA Browser:
  * Check "Advanced", "Safe Management", "Account Management" permissions for the 3 test safes.

Create more test accounts In PrivateArk client:
* Create "admin/Cyberark1" user
* Create "bastion_std_usr" and "bastion_test_usr" users with any random password
  * Add "bastion_test_usr" to "Vault Admins" group

In PVWA browser, add "bastion_test_usr" to "sample-it-dept" safe as Members, no special permission needed.

#### Platforms and Apps
With a freshly installed CyberArk,
* Activate "Oracle" platform
* Create and activate "sample_group" as a "group platform".

Finally, create two apps, "TestApp" and "TestApp2".

### Troubleshoot Test Issues
* `PASWS167E There are some invalid parameters`: The secrets should not include "," or "<".
* `PASWS159E Parameter [manualManagementReason] cannot be specified with parameter [enableAutomaticManagement]=[True]`: 
  all the test accounts the "manualManagementReason" need to be empty, if `enableAutomaticManagement == True`.
* `The number of concurrent dynamic sessions for user admin_bot has reached its limit (300)`: Make sure the tearDown
  logs off.
* `PASWS032E Platform [Oracle] is not active`: The Oracle platform is not activated.


## Update documentation

If your commit has an impact on documentation, please don't forget to update it accordingly.