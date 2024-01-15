# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-15
### Changes
- Add support to provide "Reason" when retrieving passwords
- Update documentation for testing

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
