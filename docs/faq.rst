FAQ
=======

How to integrate aiobastion with my "regular" sync programs ?
-----------------------------------------------------------------
Basically, we just need to call asyncio.run() to run async code in sync function.

    * Login the first time and keep track of your EPV object
    * Reuse it each time you need

.. code-block:: python

    import asyncio
    import sys
    import time

    import aiobastion
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


    async def logoff_cyberark(epv_session):
        await epv_session.logoff()


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


    if __name__ == "__main__":
        main()



How to reuse my token for separate programs ?
----------------------------------------------------------------------

If you are using it through a website and you want the client to keep his credentials in cookies:
    * Store the serialized EPV session in user session
    * Rebuild the EPV object using the serialized object that contains the token.
    * Don't forget to check if your token is still valid in Cyberark before reusing it!

If you are running multiple event loops but inside the same program:
    * Call login function multiple time with you config file, if the token was obtained it will be reused.

Here's an example of serialization / deserialization:

.. code-block:: python

    # Save your session in json
    epv_json = epv_session.to_json()

    # Pass information to another program the way you want

    # Other program:
    # Utility function to rebuild EPV object from serialized session
    async def get_session(epv_session):
        epv = aiobastion.EPV(serialized=epv_session)
        if not await epv.check_token():
            # Ensure that the token is still valid
            raise GetTokenException
        return epv

    epv = asyncio.run(get_session(epv_json))
    safes = asyncio.run(list_safes(epv))
    print(f"List of Safes : {safes}")

    # For security reasons, you want to logoff at the end.
