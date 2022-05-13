# Contributing

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
- Then, generate some accounts with mockaroo and the following schemas : https://www.mockaroo.com/b41fedb0
- Create the associated safes : sample-it-dept,sample-iaadmins,sample-coolteam
- Import the data (with bulk upload)
- Create the configuration file for your testing Vault
- Check the \_\_init__.py file for the location of this file
- Ensure all tests are passed (or skipped)


## Update documentation

If your commit has an impact on documentation, please don't forget to update it accordingly.