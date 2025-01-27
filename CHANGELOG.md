# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.9] - 2025-27-01
### Changes
- added include_accounts option to get_safe_details
- 

## [0.1.8] - 2024-10-01
### Changes
- Added a function to get user's safes
- Added list members linked function
- Added the connection_component_by_platform function in utilities
- Changed the return of connection_component_usage from string to list of dict
- Adding PrivilegedAccount object directly in epv class to allow user to import it

### Bugfixes
- Added a semaphore in the move function to avoid mass creation before mass deletion (we ensure that max 50 accounts are created before the old accounts are deleted)

## [0.1.7] - 2024-08-01
### Changes
Configuration file changes:
  - Existing section
      - "AIM" section
          - Added "passphrase" field in "AIM" section to handle AIM PEM encrypted certificate.

  - New section:
    - "accounts" section defined the EPV.account option fields:
          handle "LOGON_ACCOUNT_INDEX" and "RECONCILE_ACCOUNT_INDEX" definition.
          Those definition has been moved from the 'custom' section.

    - "safe" section defined the EPV.safe option fields:
          handle "cpm" and "retention" definition.
          Those definition has been moved from the global section.

    - "api_options" section defined the new global API options.
          - "deprecated_warning" field to enable/disable deprecated warning (default is true = enable)

Serialization changes:
  - Existing keys:
      - "AIM"  (dictionary)
        - Added "passphrase" field in "AIM" section to handle AIM encrypted certificate.
        - Default value for "verify" field is now "True" (ROOT certificate authority (CA) will be validated by default).

  - New keys dictionary in serialization:
    - "account" key (dictionary):
          - "LOGON_ACCOUNT_INDEX" and "RECONCILE_ACCOUNT_INDEX" fields.
    - "safe" key (dictionary):
          - "cpm" and "retention" fields.
    - "api_options" key (dictionary):
          - "deprecated_warning" field.

  - keys moved:
      - from the global section to "account"
          - "LOGON_ACCOUNT_INDEX" and "RECONCILE_ACCOUNT_INDEX" fields.
      - from the "custom" section to "safe"
          - "cpm" and "retention" fields.


Functions changes:
  - Safe class:
      - Added an "update" function

  - EPV class:
      - "login_with_aim" function has been modified to force some parameters to be specified in the form key=value.
          For example: epv_env.login_with_aim(passphrase="Hello123Word!")
          - "root_ca" parameter is now deprecated, you should use the "verify" parameter.

      - "to_json" now return a dictionary for keys: "safe", "account" and "api_options".

raise exception changes:
  - new exception "CyberarkNotFoundException" will be raise for a http error 404 (page not found) instead of "CyberarkException".

Internal modification for a better management for file configuration and serialization mainly in config.py and cyberark.py.

### Bugfixes
- Fixed a bug where multiple file category where not all updated in some conditions

## [0.1.6] - 2024-03-14
### Bugfixes
- add keep_cookies to serialized aim fields


## [0.1.5] - 2024-03-08
### Bugfixes
- Tests were not all functional
- EPV_AIM constructor needed keep_cookie when instantiated from config
- Clarifications in docstring

## [0.1.4] - 2024-03-05
### Bugfixes
- The "retain cookies" feature in 0.1.1 has a bug (cookies were not retained). 0.1.1 had no broken changes, but the
  new feature was not functional. The issue is fixed here.

## [0.1.3] - 2024-03-04
### Changes
- Adding some tests
- Adding some functions related to Account Groups

## [0.1.2] - 2024-02-08
### Changes
- Better SSL handling for AIM
- Useless functions removal
- Updating documentation

## [0.1.1] - 2024-02-03
### Changes
- Add "get_safe_details" method
- Add support for "custom" configs to override the default logon and reconcile account index.
  **DO NOT USE, deprecated in 0.1.7**.
- Add support to retain cookies during login, and use for subsequent API calls for load-balanced PVWAs.

## [0.1.0] - 2024-01-26
### Changes
- Adding some debug information
- Code refactoring for aim part

## [0.0.31] - 2024-01-15
### Changes
- Add support to provide "Reason" when retrieving passwords
- Update documentation for testing

## [0.0.30] - 2024-16-01
### Changes
- Adding platform deactivation

### Bugfixes
- Typo in platform suppression
- request_params not initialized when checking token

## [0.0.29] - 2024-11-01
### Changes
- Adding AIM related functions get_password_aim and get_secret_aim
- Better handling of config files
- Documentation refactoring

## [0.0.28] - 2023-10-12
### Changes
- Changing projet packaging to pyproject.toml
- Implementing mapping protocol

## [0.0.27] - 2023-10-04
### Bugfixes
- resume_password_management and disable_password_management now return list of updated Accounts (instead of dict)

## [0.0.26] - 2023-06-07
### Changes
- Removing abstract.py only used for internal development
- Refactoring docs to benefit from autodoc features

## [0.0.25] - 2023-05-31
### Changes
- Checking name of the object in _filter_acccount
- Adding some docstrings
- Changing return of update_using_list function (now returns PrivilegedAccount objects)
- Renamed "get_password_version" to "get_secret_version" to respect CA's nomenclature
- Adding some tests for accounts functions

### Bugfixes
- Fix bug where coroutine was not awaited in update_file_category

## [0.0.24] - 2023-04-07
### Changes
- Adding "search_in" in add_member to allow search in directory

### Bugfixes
- Fixed a bug where getting group ID was case-sensitive
- Verify username existence before adding it to safe is a regression for group add from directory

## [0.0.21] - 2023-04-06
### Bugfixes
- Fixed circular imports

## [0.0.20] - 2023-03-23
### Changes
- adding add application and delete application functions
- Verify username existence before adding it to safe
- Verify safe existence before adding user to safe
- Adding some objects in abstract for typehint
- Adding del_member function

### Bugfixes
- Fixed a bug where checking if a user exists was case-sensitive
- Fixed a bug where checking an empty safe name existence resulted in an exception

## [0.0.19] - 2023-03-23
### Changes
- users.list now accepts details and extended_details

### Bugfixes
- Fixing tests in test_safe.py

## [0.0.18] - 2023-03-09
### Bugfixes
- Fixed print in restore_last_cpm_version_by_cpm function

## [0.0.17] - 2023-03-09
### Changes
- add_member function now takes the permissions as argument instead of a profile
- allowing function "safe.list" to get details for backward comp
- adding system_health related functions

### Bugfixes
- Fixed the type of args for safe search function from string to boolean
- Changing filecategory now returns the updated account (instead of None)


## [0.0.16] - 2023-03-09
### Changes
- Added the add / delete functions in users
- Added the ability to recover password versions
- Added the ability to set a password
- Added the ability to set a password from versions
- Improved the FC update functions
- Improved the safe search functions

### Bugfixes
- Raise the ChallengeResponseException properly
