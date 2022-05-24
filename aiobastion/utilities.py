import asyncio
import copy

from .exceptions import *
import logging
from .abstract import Vault, PrivilegedAccount


def clone_privileged_account(account: PrivilegedAccount, replace: dict, update_name=True) -> PrivilegedAccount:
    new_a = copy.deepcopy(account)
    for k, v in replace.items():
        try:
            getattr(new_a, k)
            setattr(new_a, k, v)
        except AttributeError:
            new_a.platformAccountProperties[k] = v
    if update_name:
        new_a.name = new_a.get_name()
    return new_a


class Utilities:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def cpm_change_failed_accounts(self, address, username_filter: list = None):
        """
        CPM Change for "red" accounts
        :param address: exact value of field Address in EPV
        :param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for acc in accounts:
            if username_filter is not None and acc.userName not in username_filter:
                continue
            if (acc.secretManagement['automaticManagementEnabled'] is False) or \
                    ("status" not in acc.secretManagement) or (acc.secretManagement["status"] == 'failure'):
                try:
                    await self.epv.account.change_password(acc)
                    logging.info(f"{address};{acc.userName};MARKED FOR CHANGE")
                except CyberarkAPIException:
                    logging.error(f"{address};FAILED MARK CHANGE FOR {acc.userName}")


    async def cpm_change(self, address,username_filter: list = None):
        """
        CPM Change a list of accounts for a address
        @param address: exact value of field Address in EPV
        @param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                logging.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                await self.epv.account.change_password(account)
                logging.info(f"EPV;MARKED FOR CHANGE;{account.userName};{account.address}")
            except CyberarkAPIException:
                logging.error(f"EPV;MARK CHANGE FAILED;{account.userName};{account.address}")


    async def manual_set_password(self, address, password, username_filter: list):
        """
        CPM Change a list of accounts for a address
        :param address: exact value of field Address in EPV
        :param password: New password to put on the address
        :param username_filter: Which accounts to put the password on (list)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if account.userName not in username_filter:
                logging.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                if await self.epv.account.set_password(account.id, password):
                    logging.info(f"{account.userName};{address};Password successfully changed")
                else:
                    logging.info(f"{account.userName};{address};Password NOT changed")
            except Exception as err:
                logging.error(f"{account.userName};{address};An error occured when trying to change password : {err}")


    async def reconcile(self, address, username_filter: list = None):
        """
        Reconcile a list of accounts for an address
        :param address: exact value of field Address in EPV
        :param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                logging.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                await self.epv.account.reconcile(account)
                logging.info(f"EPV;MARKED FOR RECONCILE;{account.userName};{account.address}")
            except CyberarkAPIException:
                logging.error(f"EPV;MARK FOR RECONCILE FAILED;{account.userName};{account.address}")


    async def reconcile_failed_accounts(self, address: str, username_filter: list = None):
        """
        Reconcile a list of accounts for a address if they are red in PVWA
        @param address: exact value of field Address in EPV
        @param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                logging.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            if "status" not in account.secretManagement or account.secretManagement["status"] == 'failure'\
                    or account.secretManagement['automaticManagementEnabled'] is False:
                try:
                    await self.epv.account.reconcile(account)
                    logging.info(f"EPV;MARKED FOR RECONCILE;{account.userName};{account.address}")
                except CyberarkAPIException:
                    logging.error(f"EPV;RECONCILE_FAILED;{account.userName};{account.address}")


    async def migrate_platform(self, old_platform: str, new_platform: str, address_filter: list = None):
        """
        Migrate all accounts from old platform to new platform
        :param old_platform: Platform to migrate from
        :param new_platform: Platform to migrate to
        :param address_filter: A list of address (exact value of field address) to filter on (default ALL address)
        """
        for acc in await self.epv.account.search_account_by(platform=old_platform):
            if address_filter is not None and acc.address not in address_filter:
                logging.debug(f"{acc.address};{acc.userName};Filtered by user !")
                continue
            data = [{"path": "/platformID", "op": "replace", "value": new_platform}]
            try:
                await self.epv.account.update_using_list(acc.id, data)
                logging.info(f"{acc.address};{acc.userName};Platform changed")
            except Exception as e:
                logging.error(f"{acc.address};{acc.userName};An error occured when trying to change platform : {e}")


    async def account_status(self, address: str, accounts: list):
        """
        Give the CPM status of accounts for an address
        :param address: Exact match of address field
        :param accounts: List of accounts to get the status for
        :return: A string with True and the number of good accounts found, or False with list of failed accounts
        """
        status = True
        failed = []
        reason = ""
        good = 0
        accs = await self.epv.account.search_account_by(address=address)

        if len(accs) == 0:
            logging.info(f"{address};Introuvable !")

        for acc in accs:
            if "status" not in acc.secretManagement or acc.secretManagement["status"] == 'failure':
                if acc.userName in accounts:
                    failed.append(acc.userName)
                    status = False
            elif acc.secretManagement['automaticManagementEnabled'] is False:
                reason = acc.secretManagement['manualManagementReason']
                if acc.userName in accounts:
                    failed.append(acc.userName)
                    status = False
            else:
                good += 1

        if status:
            return f"{address};True;{good}"
        else:
            return f"{address};False;{failed};{reason}"


    async def delete_accounts(self, address: str, safe_pattern_filter: str = ""):
        """
        Delete all accounts associated to an address
        :param safe_pattern_filter: Safe pattern you want to IGNORE
        :param address: address file category exact match
        :return: A list of deleted accounts
        """
        del_acc = await self.epv.account.search_account_by(address=address)
        results = []
        for acc in del_acc:
            if safe_pattern_filter != "" and safe_pattern_filter in acc.safeName:
                logging.info(f"EPV;User filter matched;{acc.userName};{acc.address}")
                continue
            # logging.info(f"EPV;DELETE;{acc.userName};{acc.address}")
            if await self.epv.account.delete(acc):
                results.append(acc.name)
        return results

    async def stack_tasks(self, list_of_address: list, function, **args):
        task_list = []
        for address in list_of_address:
            task_list.append(function(address=address, epv=self.epv, **args))
        return await asyncio.gather(*task_list)

    # not tested yet but works for sure :)
    async def stack_with_concurrency(self, list_of_address:list, function, max_tasks=10, return_exceptions=False, **args):
        """
        Quickly apply concurrently a function to a list of address

        :param list_of_address: list of address to apply the function on
        :param function: the function
        :param max_tasks: max concurrent tasks
        :param return_exception: whether the function will return Exception as normal return, or raise
        :param args: dict of args of the function
        :return: list of return in the order of adresses
        """
        semaphore = asyncio.Semaphore(max_tasks)

        async def sem_fun(fun, **a):
            async with semaphore:
                return await fun(**a)

        return await asyncio.gather(*(
            sem_fun(function, adress=address, epv=self.epv, **args) for address in list_of_address),
                                    return_exceptions=return_exceptions)

    # add a semaphore to any task
    async def gather_with_concurrency(self, n: int, *tasks, return_exceptions=False):
        """
        Gather a list of coros with concurrency

        :param n: Number of max coros launched at the same time
        :param tasks: task1, task2, ..., tasksn (if you have a list then prefix it with *)
        :param return_exceptions: if set to True, exceptions are returned as regular results, instead of being raised
        :return: List of results in the same order as the tasks
        """
        semaphore = asyncio.Semaphore(n)

        async def sem_task(task):
            async with semaphore:
                return await task
        return await asyncio.gather(*(sem_task(task) for task in tasks), return_exceptions=return_exceptions)

    async def clone_address(self, address: str, replace: dict, update_name=True):
        """
        Find all accounts with an address, and clone them with new parameters

        :param update_name: automatic update of the address name, True by default
        :param address: address of accounts to find
        :param replace: FC to replace : ex {"address": "new_address", "safeName": "new_safe"}
        :return:
        """
        accounts = await self.epv.account.search_account_by(address=address)
        clones = []
        for a in accounts:
            new_a = clone_privileged_account(a, replace, update_name)
            clones.append(new_a)

        return await self.epv.account.add_account_to_safe(clones)

    async def clone_account(self, address: str, username: str, replace, update_name=True):
        """
        Find an account identified by address and username, and clone it with new parameters
        :param address: Address of account to clone
        :param username: Username of account to clone
        :param replace: dict with replace ex {"address": "new_address", "safeName": "new_safe"}
        :param update_name: automatic update of the name
        :return: Boolean telling if the account was created
        """
        accounts = await self.epv.account.search_account_by(address=address, username=username)
        if len(accounts) != 1:
            raise AiobastionException(f"More than one address was found with {address} and {username}")
        else:
            account = accounts[0]
        new_account = clone_privileged_account(account, replace, update_name)

        return await self.epv.account.add_account_to_safe(new_account)
