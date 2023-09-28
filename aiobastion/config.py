# -*- coding: utf-8 -*-

import sys
import yaml
from .exceptions import AiobastionConfigurationException

class Config:
    # Default value
    CYBERARK_DEFAULT_TIMEOUT = 30
    CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS = 10
    CYBERARK_DEFAULT_RETENTION = 10

    def __init__(self, configfile):
        # Global section Initialisation
        self.AIM = None
        self.Connection = None
        self.CPM = ""
        self.customIPField = None
        self.Label = None
        self.retention = None

        # Connection section Initialisation
        self.appid = None
        self.authtype = "Cyberark"
        self.password = None
        self.user_search = None
        self.username = None

        # PVWA section Initialisation
        self.PVWA = None
        self.max_concurrent_tasks = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS
        self.timeout = Config.CYBERARK_DEFAULT_TIMEOUT
        self.PVWA_CA = False

        with open(configfile, 'r') as config:
            configuration = yaml.safe_load(config)


        # Change global section name in lowercase
        for k in list(configuration.keys()):
            keyname = k.lower()

            if keyname not in [ "aim", "connection", "cpm", "customipfield", "label", "pvwa", "retention"]:
                #raise AiobastionConfigurationException(f"Unknown section '{k}' in configuration file")
                print(f"Warning - aiobastion - Unknown section '{k}' in configuration file", file=sys.stderr)
                continue

            if k != keyname:
                # change the keyname in lowercase
                configuration[keyname] = configuration.pop(k)

        # Read global sections in the right order
        if "connection" in configuration and configuration["connection"]:
            self._read_section_connection(configuration["connection"])

        if "pvwa" in configuration and configuration["pvwa"]:
            self._read_section_pvwa(configuration["pvwa"])

        if "aim" in configuration and configuration["aim"]:
            self._read_section_aim(configuration["aim"])

        if "cpm" in configuration:
            self.CPM = configuration["cpm"]
        if "label" in configuration:
            self.label = configuration["label"]
        if "customipfield" in configuration:
            self.customIPField = configuration["customipfield"]
        if "retention" in configuration:
            self.retention = Config._to_integer("retention", configuration["retention"])


    def _read_section_connection(self, configuration):
        for k in list(configuration.keys()):
            keyname = k.lower()

            if keyname == "appid":
                self.appid    = configuration[k]
            elif keyname == "authtype":
                self.authtype = configuration[k]
            elif keyname == "password":
                self.password = configuration[k]
            elif keyname == "user_search":
                self.user_search = configuration[k]
            elif keyname == "username":
                self.username = configuration[k]
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{k}' for section 'connection' in configuration file")


        # user_search dictionary Validation
        if self.user_search:
            if not isinstance(self.user_search, dict):
                raise AiobastionConfigurationException(f"Malformed attribute 'user_search' within section 'connection' in configuration file: {self.user_search!r}")

            # Check user_search parameter name
            _getPassword_request_parm = [ "safe", "folder", "object",  "username", "address", "database", "policyid", "reason"
                                        , "connectiontimeout", "query", "queryformat", "failrequestonpasswordchange" ]

            for k in self.user_search:
                keyname = k.lower()
                if keyname not in _getPassword_request_parm:
                    raise AiobastionConfigurationException(f"Unknown attribute '{k}' for section 'connection/user_search' in configuration file")

                if k != keyname:
                    self.user_search[keyname] = self.user_search.pop(k)

    def _read_section_pvwa(self, configuration):
        synonyme_PVWA_CA = 0
        synonyme_max_concurrent_tasks = 0

        for k in list(configuration.keys()):
            keyname = k.lower()

            if keyname == "host":
                self.PVWA = configuration[k]
            elif keyname == "timeout":
                self.timeout = Config._to_integer("PVWA/" + k, configuration[k])
            elif keyname == "maxtasks" or keyname == "max_concurrent_tasks":
                self.max_concurrent_tasks = Config._to_integer("PVWA/" + k, configuration[k])
                synonyme_max_concurrent_tasks += 1
            elif keyname == "verify" or keyname == "ca":
                self.PVWA_CA = configuration[k]
                synonyme_PVWA_CA += 1
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{k}' for section 'PVWA' in configuration file")

        if synonyme_PVWA_CA > 1:
            raise AiobastionConfigurationException(f"Duplicate synonyme parameter: 'ca', 'verify' in section 'PVWA'. Specify only one of them.")

        if synonyme_max_concurrent_tasks > 1:
            raise AiobastionConfigurationException(f"Duplicate synonyme parameter: 'maxtasks', 'max_concurrent_tasks' in section 'PVWA'. Specify only one of them.")


    def _read_section_aim(self, configuration):
        configuration_aim = {
             "appid":                None       # Default = Connection (appid)
            ,"cert":                 None
            ,"host":                 None       # Default = PVWA (host)
            ,"key":                  None
            ,"max_concurrent_tasks": None       # Default = PVWA (max_concurrent_tasks)
            ,"verify":               None       # Default = PVWA (PVWA_CA)
            ,"timeout":              None       # Default = PVWA (timeout)
        }

        synonyme_verify = 0
        synonyme_max_concurrent_tasks = 0

        for k in list(configuration.keys()):
            keyname = k.lower()

            if keyname in ["appid", "cert", "host", "key"]:
                configuration_aim[keyname] = configuration[k]
            elif keyname == "timeout":
                configuration_aim[keyname] = Config._to_integer("AIM/" + k, configuration[k])
            elif keyname in  ["maxtasks", "max_concurrent_tasks"]:
                configuration_aim["max_concurrent_tasks"] = Config._to_integer("AIM/" + k, configuration[k])
                synonyme_max_concurrent_tasks += 1
            elif keyname in ["ca", "verify"] :
                configuration_aim["verify"] = configuration[k]
                synonyme_verify += 1
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{k}' for section 'AIM' in configuration file")

        if synonyme_verify > 1:
            raise AiobastionConfigurationException(f"Duplicate synonyme parameter: 'ca', 'verify' in section 'AIM'. Specify only one of them.")

        if synonyme_max_concurrent_tasks > 1:
            raise AiobastionConfigurationException(f"Duplicate synonyme parameter: 'maxtasks', 'max_concurrent_tasks' in section 'AIM'. Specify only one of them.")


        self.AIM = configuration_aim

        # If not defined used Connection definitions to complete initialization.
        if self.AIM["appid"] is None:
            self.AIM["appid"]   = self.appid

        # If not defined used PVWA definitions to complete initialization.
        if self.AIM["host"] is None:
            self.AIM["host"]    = self.PVWA
        if self.AIM["timeout"] is None:
            self.AIM["timeout"] = self.timeout
        if self.AIM["max_concurrent_tasks"] is None:
            self.AIM["max_concurrent_tasks"] =  self.max_concurrent_tasks
        if self.AIM["verify"] is None:
            self.AIM["verify"]  = self.PVWA_CA



    @staticmethod
    def _to_integer(section_key, val):
        try:
            v = int(val)
        except ValueError:
            raise AiobastionConfigurationException(f"Invalid integer '{section_key}' in configuration file: {val!r}")

        return v


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
        if isinstance(i,list): rt.extend(flatten(i))
        else: rt.append(i)
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
