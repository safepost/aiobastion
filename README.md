# aiobastion

**aiobastion** is a simple and fully asynchronous framework for [Cyberark API](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm) written in Python 3.11 with [asyncio](https://docs.python.org/3/library/asyncio.html) and [aiohttp](https://github.com/aio-libs/aiohttp). 
It helps you to manage your Cyberark implementation faster and in an intuitive way.


## Examples
See [examples of usage](https://aiobastion.readthedocs.io/en/latest/started.html#examples) in the [documentation](https://aiobastion.readthedocs.io/en/latest/index.html)

## Quick (and dirty) start
### List safes

Here's a minimal python snippet to list safes

```python 
import aiobastion
import asyncio

from aiobastion import GetTokenException


async def main():
    # Define your PVWA host here
    pvwa_host = "pvwa.mycompany.fr"
    vault = aiobastion.EPV(serialized={'api_host': pvwa_host})
    
    # Define login and password
    login = input("Login: ")
    password = input("Password: ")

    # Login to the PVWA
    try:
        await vault.login(login, password)
    except GetTokenException as err:
        print(f"An error occured while login : {err}")
        await vault.close_session()
        exit(0)

    # Working with PVWA
    async with vault as epv:
        # For example, listing all safes
        safes = await epv.safe.list()
        for s in safes:
            print(s)

if __name__ == '__main__':
    asyncio.run(main())

```



## Getting started
[Define a config file](https://aiobastion.readthedocs.io/en/latest/login.html#define-a-configuration-file), and start using functions to avoid spending hours in annoying tasks in the PVWA :

* [Accounts manipulation](https://aiobastion.readthedocs.io/en/latest/accounts.html)
* [Safe manipulation](https://aiobastion.readthedocs.io/en/latest/safe.html)
* [User manipulation](https://aiobastion.readthedocs.io/en/latest/users.html)
* Check the documentation for more


## Documentation
The documention is hosted on readthedocs : https://aiobastion.readthedocs.io/en/latest/index.html

## Rationale

I've been working on Cyberark projects for years and I see everywhere a profusion of scripts, very often complicated and long to execute for very simple tasks (sometimes even with a "do not turn off" post-it on the screen).
This package makes it quick and easy to accomplish without having to deal with the specifics of the Cyberark API.
The acquisition time may be longer than for other well-known libraries, but, believe me, you will save this time very quickly.