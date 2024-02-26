import asyncio
import sys
import time

import aiobastion
import tests
from aiobastion import GetTokenException


# Automatic login using configuration setup
async def login_cyberark():
    # tests.CONFIG="/path/to/config_file.yml"
    epv_env = aiobastion.EPV(tests.CONFIG)
    try:
        await epv_env.login()
    except GetTokenException as err:
        raise f"Error while trying to login to the vault : {err}"
    return epv_env


# Utility function to rebuild EPV object from serialized session
async def get_session(epv_session):
    epv = aiobastion.EPV(serialized=epv_session)
    if not await epv.check_token():
        # Ensure that the token is still valid
        raise GetTokenException
    return epv

async def logoff_cyberark(epv_session):
    await epv_session.logoff()

async def list_safes_2(epv_session):
    epv = await get_session(epv_session)
    print(epv.session)

    return epv.session


# Some async function that performs tasks into PVWA
async def list_safes(epv):
    return await epv.safe.list()


# Sync function
def main():
    print("Main program started python", sys.version)

    # Async login to Cyberark
    epv_session: aiobastion.EPV = asyncio.run(login_cyberark())

    # Doing sync stuff
    for i in range(3):
        time.sleep(0.5)
        print(f"Main program iteration {i}")

    # Doing async stuff
    safes = asyncio.run(list_safes(epv_session))
    print(f"List of Safes : {safes}")

    # Close connexion at the end, because we don't use context manager
    asyncio.run(logoff_cyberark(epv_session))
    print("All good !")

    global epv_json
    epv_json = epv_session.to_json()

def main2():
    epv = asyncio.run(get_session(epv_json))
    # Doing async stuff
    safes = asyncio.run(list_safes(epv))
    print(f"List of Safes : {safes}")
    # pass

if __name__ == "__main__":
    # logging.basicConfig(
    #     level=logging.DEBUG,
    #     # level=logging.INFO,
    #     format='%(asctime)s %(levelname)08s %(name)s %(message)s',
    # )

    main()
