# -*- coding: utf-8 -*-

import yaml

_default_timeout = 30
_default_max_concurrent_tasks = 10

class Config:
    def __init__(self, configfile):
        with open(configfile, 'r') as config:
            document = yaml.safe_load(config)

        try:
            if "Connection" not in document or document["Connection"] is None:
                self.username = None
                self.password = None
                self.authtype = "Cyberark"
                self.appid = None
                self.user_search = None
            else:
                for k in list(document["Connection"].keys()):
                    # Convert key name in lowercase
                    keyname = k.lower()
                    if k != keyname:
                        document["Connection"][keyname] = document["Connection"].pop(k)

                if "username" in document["Connection"]:
                    self.username = document["Connection"]["username"]
                else:
                    self.username = None
                if "password" in document["Connection"]:
                    self.password = document["Connection"]["password"]
                else:
                    self.password = None
                if "appid" in document["Connection"]:
                    self.appid = document["Connection"]["appid"]
                else:
                    self.appid = None
                if "authtype" in document["Connection"]:
                    self.authtype = document["Connection"]["authtype"]
                else:
                    self.authtype = None

                if "user_search" in document["Connection"]:
                    user_search = document["Connection"]["user_search"]

                    if not isinstance(user_search, dict):
                        raise ValueError(f"Malformed configuration file, Connection section, User_search : {user_search!r}")

                    # Check user_search parameter name
                    _getPassword_request_parm = [ "safe", "folder", "object",  "username", "address", "database", "policyid", "reason"
                                                , "connectiontimeout", "query", "queryformat", "failrequestonpasswordchange" ]

                    for k in user_search:
                        key_lower = k.lower()
                        if key_lower not in _getPassword_request_parm:
                           raise ValueError(f"Unknow Connection/Username_search parameter in configuration file: {k}={user_search[k]!r}")

                        if k != key_lower:
                            user_search[key_lower] = user_search.pop(k)

                    self.user_search = user_search
                else:
                    self.user_search = None

            if "PVWA" in document:
                for k in list(document["PVWA"].keys()):
                    # Convert key name in lowercase
                    keyname = k.lower()
                    if k != keyname:
                        document["PVWA"][keyname] = document["PVWA"].pop(k)

                # 'MaxTasks' becomes 'max_concurrent_tasks'
                if "maxtasks" in document["PVWA"] and "max_concurrent_tasks" in document["PVWA"]:
                    raise KeyError(f"Mutually exclusive parameters: MaxTasks and max_concurrent_tasks in PVWA section")

                if "maxtasks" in document["PVWA"]:
                    document["PVWA"]["max_concurrent_tasks"] = document["PVWA"].pop("maxtasks")

                # 'CA' becomes 'verify'
                if "verify" in document["PVWA"] and "ca" in document["PVWA"]:
                    raise KeyError(f"Mutually exclusive parameters: 'verify' and 'CA' in PVWA section")

                if "ca" in document["PVWA"]:
                    document["PVWA"]["verify"] = document["PVWA"].pop("ca")

                if "host" in document["PVWA"]:
                    self.PVWA = document["PVWA"]["host"]
                if "verify" in document["PVWA"]:
                    self.verify = document["PVWA"]["verify"]
                else:
                    self.verify = False
                if "timeout" in document["PVWA"]:
                    self.timeout = int(document["PVWA"]["timeout"])
                else:
                    self.timeout = _default_timeout
                if "max_concurrent_tasks" in document["PVWA"]:
                    self.max_concurrent_tasks = int(document["PVWA"]["max_concurrent_tasks"])
                else:
                    self.max_concurrent_tasks = _default_max_concurrent_tasks

            if "AIM" in document and document["AIM"] is not None:
                # Convert keyname to lowercase and validate it
                #    problem with key name "key" need to use list()
                for k in list(document["AIM"].keys()):
                    keyname = k.lower()

                    if keyname not in ["host", "appid", "cert", "key",  "verify", "timeout", "max_concurrent_tasks", "maxtasks", "ca"]:
                        raise KeyError(f"Unknown parameter in configuration file - AIM section {k}: {document['AIM'][k]!r}")

                    if keyname != k:
                        document["AIM"][keyname] = document["AIM"].pop(k)

                # "maxtasks" becomes "max_concurrent_tasks"
                if "maxtasks" in document["AIM"] and "max_concurrent_tasks" in document["AIM"]:
                    raise KeyError(f"Mutually exclusive parameters: 'maxtasks' and 'max_concurrent_tasks' in AIM section")

                if "maxtasks" in document["AIM"]:
                    document["AIM"]["max_concurrent_tasks"] = document["AIM"].pop("maxtasks")

                # "CA" becomes "verify"
                if "verify" in document["AIM"] and "ca" in document["AIM"]:
                    raise KeyError(f"Mutually exclusive parameters: 'verify' and 'ca' in AIM section")

                if "ca" in document["AIM"]:
                    document["AIM"]["verify"] = document["AIM"].pop("ca")

                # Set default value, if not defined used PVWA value to complete initialization.
                document["AIM"].setdefault("host",                  getattr(self, "PVWA",    None))
                document["AIM"].setdefault("appid",                 getattr(self, "appid",   None))
                document["AIM"].setdefault("verify",                getattr(self, "verify", False))
                document["AIM"].setdefault("timeout",               getattr(self, "timeout", _default_timeout))
                document["AIM"].setdefault("max_concurrent_tasks",  getattr(self, "max_concurrent_tasks", _default_max_concurrent_tasks))

                # Integer conversion
                document["AIM"]["timeout"] = int(document["AIM"]["timeout"])
                document["AIM"]["max_concurrent_tasks"] = int(document["AIM"]["max_concurrent_tasks"])

                self.AIM = document["AIM"]
            else:
                self.AIM = None

            if "CPM" in document:
                self.CPM = document["CPM"]
            else:
                self.CPM = ""
            if "retention" in document:
                self.retention = int(document["retention"])
            else:
                self.retention = 30
            if "customIPField" in document:
                self.customIPField = document["customIPField"]
            else:
                self.customIPField = None
        except AttributeError as e:
            raise ValueError(f"Malformed configuration file : {str(e)}")

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
