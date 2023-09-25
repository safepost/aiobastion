# -*- coding: utf-8 -*-
import os
import yaml

from aiobastion.exceptions import AiobastionConfigurationException

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')

class Config:
    # Default value
    CYBERARK_DEFAULT_TIMEOUT = 30
    CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS = 10
    CYBERARK_DEFAULT_RETENTION = 10

    def __init__(self, configfile):
        # Attributes file
        with open(CONFIG_PATH, "r") as attributes_file:
            attributes = yaml.safe_load(attributes_file)

        # User Config file
        with open(configfile, 'r') as config:
            user_configuration_file = yaml.safe_load(config)

        # Lower case dicts
        lower_user_config = Config._lowercase(user_configuration_file)

        self.hydrate(attributes, lower_user_config)

        # if len(lower_user_config) == 0:
        self.warn_user(lower_user_config)

        for _k in self.__dict__.keys():
            print(f"Config.{_k} : {getattr(self,_k)} ")

    @staticmethod
    def _lowercase(obj):
        """ Make dictionary lowercase """
        if isinstance(obj, dict):
            return {k.lower(): Config._lowercase(v) for k, v in obj.items()}
        else:
            return obj

    def hydrate(self, attributes_yaml: dict, user_config: dict, parent: dict = None):
        for a_key, a_value in attributes_yaml.items():
            # We will first detect if this is a section or not
            if any(isinstance(sub_value, dict) for _, sub_value in a_value.items()):
                # We are in a section
                try:
                    if parent is None:
                        # If config.section_name doesn't exist, we initialise it
                        try:
                            getattr(self, a_key)
                        except AttributeError:
                            setattr(self, a_key, {})

                        # We skip section if not in user_config (by choice)
                        if a_key.lower() in user_config:
                            # Then we recursively call the function with sub-dicts
                            self.hydrate(attributes_yaml[a_key], user_config[a_key.lower()], getattr(self, a_key))
                    else:
                        # Same logic
                        if a_key not in parent:
                            parent[a_key] = {}
                        if a_key.lower() in user_config:
                            self.hydrate(attributes_yaml[a_key], user_config[a_key.lower()], parent[a_key])

                except AiobastionConfigurationException as err:
                    raise AiobastionConfigurationException(f"{a_key} | {err}")

            else:
                # We are not in a section but in a final key / value dict
                default = a_value["default"] if "default" in a_value else None
                required = a_value["required"] if "required" in a_value else False
                alt_names = a_value["alternate_names"] if "alternate_names" in a_value else []

                if parent is None:
                    self.get_user_value(user_config, a_key, self, default, required, alt_names)
                else:
                    self.get_user_value(user_config, a_key, parent, default, required, alt_names)

    def set_value_with_multiple_key_names(self, key, user_config, parent: dict, key_names: list):
        if any(_k.lower() in user_config for _k in key_names):
            user_value_key_name = next(_k.lower() for _k in key_names if _k.lower() in user_config)

            if isinstance(parent, Config):
                setattr(parent, key, user_config.pop(user_value_key_name))
            else:
                parent[key] = user_config.pop(user_value_key_name)

            # We successfully assigned a key, search another matching key
            another_key_name = next((_k for _k in key_names if _k.lower() in user_config), None)
            if another_key_name is not None:
                raise AiobastionConfigurationException(
                    f"Mutually exclusive parameters: {user_value_key_name} and {another_key_name}")

            return True
        else:
            return False

    def get_user_value(self, user_config: dict, key: str, parent, default: str, required: bool, alt_names: list):
        """
        Assign the key attributes from user config to the object Config
        :param user_config: user_config dict or subdict
        :param key: they current key we want to retrieve
        :param parent: The Config object itself or a child dictionary that represent the section being processed
        :param default: The default value, or None
        :param required: Is this parameter required in config file ?
        :param alt_names: Alternate names for this key
        :return: nothing
        """
        if self.set_value_with_multiple_key_names(key, user_config, parent, alt_names + [key]):
            # We return the len of user_config to be able to clean the user_dict
            return
        elif required:
            raise AiobastionConfigurationException(f"Field \"{key}\" is mandatory, but was not found")
        elif default:
            if isinstance(parent, Config):
                setattr(parent, key, self.get_default_value(default))
            else:
                parent[key] = self.get_default_value(default)
        else:
            # Attribute "key" was not found in user dict, but no default value was provided, we ignore it
            return

    def get_default_value(self, value: str):
        """
        If a value was specified inside < > in config.yaml file, then try to get the global variable defined here
        :param value: the value as it appears in the config file
        :return: the default value, or the value of the global variable associated
        """
        if value.startswith("<") and value.endswith(">"):
            return getattr(self, value[1:-1])
        else:
            return value


    def warn_user(self, remaining_dict, section=""):
        import warnings
        """
        :param remaining_dict:
        :return:
        """
        for k, v in remaining_dict.items():
            if isinstance(v, dict):
                if len(v) > 0:
                    self.warn_user(remaining_dict[k], k)
            else:
                if section == "":
                    section = "root"
                warnings.warn(f"Section {section} Key {k} was found in configuration file, but ignored")

# No rights at all
DEFAULT_PERMISSIONS = {
    "UseAccounts": False,
    "RetrieveAccounts": False,
    "ListAccounts": False,
    "AddAccounts": False,
    "UpdateAccountContent": False,
    "UpdateAccountProperties": False,
    "InitiateCPMAccountManagementOperations": False,
    "SpecifyNextAccountContent": False,
    "RenameAccounts": False,
    "DeleteAccounts": False,
    "UnlockAccounts": False,
    "ManageSafe": False,
    "ManageSafeMembers": False,
    "BackupSafe": False,
    "ViewAuditLog": False,
    "ViewSafeMembers": False,
    "AccessWithoutConfirmation": False,
    "CreateFolders": False,
    "DeleteFolders": False,
    "MoveAccountsAndFolders": False
}

# Can create object
PROV_PERMISSIONS = dict(DEFAULT_PERMISSIONS)
PROV_PERMISSIONS.update({
    "ListAccounts": True,
    "AddAccounts": True,
    "UpdateAccountContent": True,
    "UpdateAccountProperties": True,
    "InitiateCPMAccountManagementOperations": True,
    "RenameAccounts": True,
    "DeleteAccounts": True,
    "ManageSafe": False,
    "ManageSafeMembers": False,
    "ViewSafeMembers": False,
    "AccessWithoutConfirmation": True,
    "CreateFolders": True,
    "DeleteFolders": True,
    "MoveAccountsAndFolders": True
})

MANAGER_PERMISSIONS = dict(PROV_PERMISSIONS)
MANAGER_PERMISSIONS.update({
    "ManageSafe": True,
    "ManageSafeMembers": True,
    "ViewSafeMembers": True,
})

# all to true
ADMIN_PERMISSIONS = {perm: True for perm in DEFAULT_PERMISSIONS}

# connect
USE_PERMISSIONS = dict(DEFAULT_PERMISSIONS)
USE_PERMISSIONS["UseAccounts"] = True
USE_PERMISSIONS["ListAccounts"] = True
# Connect does not necessarily require AccessWithoutConfirmation
# USE_PERMISSIONS["AccessWithoutConfirmation"] = True

# use + retrieve
SHOW_PERMISSIONS = dict(USE_PERMISSIONS)
SHOW_PERMISSIONS["RetrieveAccounts"] = True

# list accounts + audit part
AUDIT_PERMISSIONS = dict(DEFAULT_PERMISSIONS)
AUDIT_PERMISSIONS["ListAccounts"] = True
AUDIT_PERMISSIONS["ViewAuditLog"] = True
AUDIT_PERMISSIONS["ViewSafeMembers"] = True

# power user = SHOW + AUDIT
POWER_PERMISSIONS = dict(DEFAULT_PERMISSIONS)
POWER_PERMISSIONS.update({k: v for k, v in SHOW_PERMISSIONS.items() if v})
POWER_PERMISSIONS.update({k: v for k, v in AUDIT_PERMISSIONS.items() if v})

CPM_PERMISSIONS = {
    "UseAccounts": True,
    "RetrieveAccounts": True,
    "ListAccounts": True,
    "AddAccounts": True,
    "UpdateAccountContent": True,
    "UpdateAccountProperties": True,
    "InitiateCPMAccountManagementOperations": True,
    "SpecifyNextAccountContent": True,
    "RenameAccounts": True,
    "DeleteAccounts": True,
    "UnlockAccounts": True,
    "ManageSafe": False,
    "ManageSafeMembers": False,
    "BackupSafe": False,
    "ViewAuditLog": True,
    "ViewSafeMembers": False,
    "RequestsAuthorizationLevel1": False,
    "RequestsAuthorizationLevel2": False,
    "AccessWithoutConfirmation": False,
    "CreateFolders": True,
    "DeleteFolders": True,
    "MoveAccountsAndFolders": True
}

# v2 perm
V2_BASE = {
    "useAccounts": True,
    "retrieveAccounts": False,
    "listAccounts": True,
    "addAccounts": False,
    "updateAccountContent": False,
    "updateAccountProperties": False,
    "initiateCPMAccountManagementOperations": False,
    "specifyNextAccountContent": False,
    "renameAccounts": False,
    "deleteAccounts": False,
    "unlockAccounts": False,
    "manageSafe": False,
    "manageSafeMembers": False,
    "backupSafe": False,
    "viewAuditLog": False,
    "viewSafeMembers": False,
    "accessWithoutConfirmation": False,
    "createFolders": False,
    "deleteFolders": False,
    "moveAccountsAndFolders": False,
    "requestsAuthorizationLevel1": False,
    "requestsAuthorizationLevel2": False
}

V2_USE = {
    "useAccounts": True,
    "listAccounts": True,
}
V2_ADMIN = {"manageSafeMembers": True}
V2_CHANGE = {"updateAccountContent": True}
V2_SHOW = {"retrieveAccounts": True}
V2_AUDIT = {"viewAuditLog": True}


#
# # power user = SHOW + AUDIT
# V2_POWER = dict(V2_SHOW)
# V2_POWER.update({k: v for k, v in V2_AUDIT.items() if v})


def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True


def flatten(A):
    rt = []
    for i in A:
        if isinstance(i, list):
            rt.extend(flatten(i))
        else:
            rt.append(i)
    return rt


def permissions(profile: str) -> dict:
    if "admin" in profile.lower():
        return ADMIN_PERMISSIONS
    if "use" in profile.lower():
        return USE_PERMISSIONS
    if "show" in profile.lower():
        return SHOW_PERMISSIONS
    if "audit" in profile.lower():
        return SHOW_PERMISSIONS
    if "prov" in profile.lower():
        return PROV_PERMISSIONS
    if "power" in profile.lower():
        return POWER_PERMISSIONS
    if "cpm" in profile.lower():
        return CPM_PERMISSIONS
    if "manager" in profile.lower():
        return MANAGER_PERMISSIONS
    else:
        # nothing !
        return DEFAULT_PERMISSIONS


def get_v2_profile(permission) -> str:
    perms = []
    if all(t for t in [permission[k] == v for k, v in V2_ADMIN.items()]):
        perms.append("Admin")
    if all(t for t in [permission[k] == v for k, v in V2_AUDIT.items()]):
        perms.append("Audit")
    if all(t for t in [permission[k] == v for k, v in V2_SHOW.items()]):
        perms.append("Show")
    if all(t for t in [permission[k] == v for k, v in V2_CHANGE.items()]):
        perms.append("Change")
    if all(t for t in [permission[k] == v for k, v in V2_USE.items()]):
        perms.append("Use")
    if len(perms) == 0:
        perms.append("Profil Inconnu")
    return " + ".join(perms)
