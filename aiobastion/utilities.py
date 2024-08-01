import asyncio
import copy

from .accounts import PrivilegedAccount
from .exceptions import AiobastionException, CyberarkAPIException, AiobastionConfigurationException


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


def case_insensitive_getattr(obj, attr):
    for a in dir(obj):
        if a.lower() == attr.lower():
            return getattr(obj, a)


class Utilities:
    # _UTILITIES_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        self.epv = epv
        self.platform = self.Platform(epv)

        _section = "utilities"
        _config_source = self.epv.config.config_source

        for _k in kwargs.keys():
            raise AiobastionConfigurationException(f"Unknown attribute '{_section}/{_k}' in {_config_source}")

    def to_json(self):
        serialized = {}

        for attr_name in Utilities._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

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
                    self.epv.logger.info(f"{address};{acc.userName};MARKED FOR CHANGE")
                except CyberarkAPIException:
                    self.epv.logger.error(f"{address};FAILED MARK CHANGE FOR {acc.userName}")


    async def cpm_change(self, address,username_filter: list = None):
        """
        CPM Change a list of accounts for an address
        :param address: exact value of field Address in EPV
        :param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                self.epv.logger.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                await self.epv.account.change_password(account)
                self.epv.logger.info(f"EPV;MARKED FOR CHANGE;{account.userName};{account.address}")
            except CyberarkAPIException:
                self.epv.logger.error(f"EPV;MARK CHANGE FAILED;{account.userName};{account.address}")

    async def manual_set_password(self, address, password, username_filter: list = None):
        """
        Set a custom password a list of accounts for an address
        :param address: exact value of field Address in EPV
        :param password: New password to put on the address
        :param username_filter: Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                self.epv.logger.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                if await self.epv.account.set_password(account.id, password):
                    self.epv.logger.info(f"{account.userName};{address};Password successfully changed")
                else:
                    self.epv.logger.info(f"{account.userName};{address};Password NOT changed")
            except Exception as err:
                self.epv.logger.error(f"{account.userName};{address};An error occured when trying to change password : {err}")

    async def reconcile(self, address, username_filter: list = None):
        """
        Reconcile a list of accounts for an address
        :param address: exact value of field Address in EPV
        :param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                self.epv.logger.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            try:
                await self.epv.account.reconcile(account)
                self.epv.logger.info(f"EPV;MARKED FOR RECONCILE;{account.userName};{account.address}")
            except CyberarkAPIException:
                self.epv.logger.error(f"EPV;MARK FOR RECONCILE FAILED;{account.userName};{account.address}")

    async def reconcile_failed_accounts(self, address: str, username_filter: list = None):
        """
        Reconcile a list of accounts for a address if they are red in PVWA
        :param address: exact value of field Address in EPV
        :param username_filter : Put a list of username in filter to change only those accounts (default all accounts)
        """
        accounts = await self.epv.account.search_account_by(address=address)
        for account in accounts:
            if username_filter is not None and account.userName not in username_filter:
                self.epv.logger.debug(f"EPV;SKIPPING;{account.userName};{account.address}")
                continue
            if "status" not in account.secretManagement or account.secretManagement["status"] == 'failure'\
                    or account.secretManagement['automaticManagementEnabled'] is False:
                try:
                    await self.epv.account.reconcile(account)
                    self.epv.logger.info(f"EPV;MARKED FOR RECONCILE;{account.userName};{account.address}")
                except CyberarkAPIException:
                    self.epv.logger.error(f"EPV;RECONCILE_FAILED;{account.userName};{account.address}")

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
            self.epv.logger.info(f"{address};Introuvable !")

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
                self.epv.logger.info(f"EPV;User filter matched;{acc.userName};{acc.address}")
                continue
            if await self.epv.account.delete(acc):
                results.append(acc.name)
        return results

    async def clone_address(self, address: str, replace: dict, update_name=True):
        """
        Find all accounts with an address, and clone them with new parameters
        :param address: address of accounts to find
        :param replace: FC to replace : ex {"address": "new_address", "safeName": "new_safe"}
        :param update_name: automatic update of the address name, True by default
        :return: List of ID of the clones
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

    class Platform:
        def __init__(self, epv):
            self.epv = epv

        async def count_platforms(self):
            """
            Will count number of accounts linked to all platform
            Headers : ID,Platform Name,PlatformID,Type,IsActive,AccountsCount,CC1,CC2,CC3,CC4,...
            """
            all_pf = await self.epv.platform.get_target_platforms()

            count = []
            pf_id = [p["PlatformID"] for p in all_pf]
            for _p in pf_id:
                count.append(self.epv.account.search_account_by(platform=_p))
            counted = await asyncio.gather(*count)
            nb_element = {}

            for a, b in zip(pf_id, counted):
                nb_element[a] = len(b)

            result = []
            for pf in all_pf:
                plateform_id = pf["PlatformID"]
                uuid = await self.epv.platform.get_target_platform_unique_id(plateform_id)
                comps = await self.epv.platform.get_target_platform_connection_components(uuid)
                comps = ",".join([p['PSMConnectorID'] for p in comps if p['Enabled']])
                result.append(
                    f"{pf['ID']},{pf['Name']},{pf['PlatformID']},{pf['SystemType']},{pf['Active']},{nb_element[pf['PlatformID']]},{comps},")

            return result

        async def connection_component_usage(self):
            """
            Will return a list of used connection component
            """

            all_cc = await self.epv.session_management.get_all_connection_components()
            all_pf = await self.epv.platform.get_target_platforms()

            con_comp = {a['ID']: [] for a in all_cc["PSMConnectors"]}

            for pf in all_pf:
                plateform_id = pf["PlatformID"]
                uuid = await self.epv.platform.get_target_platform_unique_id(plateform_id)
                comps = await self.epv.platform.get_target_platform_connection_components(uuid)
                for _c in comps:
                    if _c["Enabled"]:
                        cc_name = _c["PSMConnectorID"]
                        if cc_name in con_comp:
                            con_comp[cc_name].append(pf['PlatformID'])
                        else:
                            print(f"Warning for {cc_name} in {pf['PlatformID']} => {_c}")
                            con_comp[cc_name] = [pf['PlatformID']]

            result = []
            for conn, pfs in con_comp.items():
                result.append(f"{conn},{len(pfs)},{','.join(pfs)}")

            return result

        async def migrate_platform(self, old_platform: str, new_platform: str, address_filter: list = None):
            """
            Migrate all accounts from old platform to new platform
            :param old_platform: Platform to migrate from
            :param new_platform: Platform to migrate to
            :param address_filter: A list of address (exact value of field address) to filter on (default ALL address)
            """
            for acc in await self.epv.account.search_account_by(platform=old_platform):
                if address_filter is not None and acc.address not in address_filter:
                    self.epv.logger.debug(f"{acc.address};{acc.userName};Filtered by user !")
                    continue
                data = [{"path": "/platformID", "op": "replace", "value": new_platform}]
                try:
                    await self.epv.account.update_using_list(acc.id, data)
                    self.epv.logger.info(f"{acc.address};{acc.userName};Platform changed")
                except Exception as e:
                    self.epv.logger.error(
                        f"{acc.address};{acc.userName};An error occured when trying to change platform : {e}")
