# -*- coding: utf-8 -*-

import sys
import yaml
from collections import namedtuple


_AttrName_def = namedtuple('_AttrName_def', ['attrName', 'defaultValue', 'multipleName_ind'])

class Config:
    def __init__(self, configfile):
        # Default value
        _default_timeout = 30
        _default_max_concurrent_tasks = 10
        _default_retention = 30

        # Define name in Yaml (in lowercase) =  (<classe attribut name>, <default value>)
        _attrname_def_global    = {
             "aim":             _AttrName_def("AIM",            None,               False)
            ,"connection":      _AttrName_def("Connection",     None,               False)
            ,"cpm":             _AttrName_def("CPM",            "",                 False)
            ,"customipfield":   _AttrName_def("customIPField",  None,               False)
            ,"label":           _AttrName_def("Label",          None,               False)
            ,"pvwa":            _AttrName_def("PVWA",           None,               False)
            ,"retention":       _AttrName_def("retention",      _default_retention, False)
        }

        _attrname_def_connection = {
             "appid":       _AttrName_def("appid",       None,       False)
            ,"authtype":    _AttrName_def("authtype",    "Cyberark", False)
            ,"password":    _AttrName_def("password",    None,       False)
            ,"user_search": _AttrName_def("user_search", None,       False)
            ,"username":    _AttrName_def("username",    None,       False)
        }

        _attrname_def_PVWA = {
             "host":                 _AttrName_def("PVWA",                 None, False)
            ,"max_concurrent_tasks": _AttrName_def("max_concurrent_tasks", _default_max_concurrent_tasks, True)
            ,"maxtasks":             _AttrName_def("max_concurrent_tasks", _default_max_concurrent_tasks, True)
            ,"timeout":              _AttrName_def("timeout",              _default_timeout, False)
            ,"ca":                   _AttrName_def("PVWA_CA",              False, True)
            ,"verify":               _AttrName_def("PVWA_CA",              False, True)
        }

        _attrname_def_AIM = {
             "appid":                _AttrName_def("appid", None, None)                 # Default = Connection
            ,"cert":                 _AttrName_def("cert", None, None)
            ,"host":                 _AttrName_def("host", None, None)                  # Default = PVWA (host)
            ,"key":                  _AttrName_def("key", None, None)
            ,"max_concurrent_tasks": _AttrName_def("max_concurrent_tasks", None, True)  # Default = PVWA (max_concurrent_tasks)
            ,"maxtasks":             _AttrName_def("max_concurrent_tasks", None, True)  # Default = PVWA (max_concurrent_tasks)
            ,"ca":                   _AttrName_def("verify", None, True)                # Default = PVWA (PVWA_CA)
            ,"verify":               _AttrName_def("verify", None, True)                # Default = PVWA (PVWA_CA)
            ,"timeout":              _AttrName_def("timeout", None, None)               # Default = PVWA (timeout)
        }

        with open(configfile, 'r') as config:
            document = yaml.safe_load(config)

        try:
            # Check global section
            document_check = {}
            self._check_yaml(document, "Global", _attrname_def_global, document_check, raise_unknown_attr=False)

            # Connection section
            self._check_yaml(document_check["Connection"], "Connection", _attrname_def_connection, raise_unknown_attr=True)

            # Connection section: Specific Validation
            if self.user_search:
                if not isinstance(self.user_search, dict):
                    raise ValueError(f"Configuration file error: Malformed attribute 'User_search' in 'Connection' section: {self.user_search!r}")

                # Check user_search parameter name
                _getPassword_request_parm = [ "safe", "folder", "object",  "username", "address", "database", "policyid", "reason"
                                            , "connectiontimeout", "query", "queryformat", "failrequestonpasswordchange" ]

                for k in self.user_search:
                    keyname = k.lower()
                    if keyname not in _getPassword_request_parm:
                        raise ValueError(f"Configuration file error: Unknown Connection/user_search attribut in configuration file: {k}={self.user_search[k]!r}")

                    if k != keyname:
                        self.user_search[keyname] = self.user_search.pop(k)

            # PVWA section
            self._check_yaml(document_check["PVWA"], "PVWA", _attrname_def_PVWA, raise_unknown_attr=True)
            self.timeout = int(self.timeout)
            self.max_concurrent_tasks = int(self.max_concurrent_tasks)

            # AIM section (optional section)
            if document_check["AIM"] is not None:
                self.AIM = {}
                self._check_yaml(document_check["AIM"], "AIM", _attrname_def_AIM, self.AIM, raise_unknown_attr=True)

                # If not defined used PVWA value to complete initialization.
                if self.AIM["appid"] is None:
                    self.AIM["appid"]   = getattr(self, "appid",   None)
                if self.AIM["host"] is None:
                    self.AIM["host"]    = getattr(self, "PVWA",    None)
                if self.AIM["timeout"] is None:
                    self.AIM["timeout"] = getattr(self, "timeout", _default_timeout)
                if self.AIM["max_concurrent_tasks"] is None:
                    self.AIM["max_concurrent_tasks"] =  getattr(self, "max_concurrent_tasks", _default_max_concurrent_tasks)
                if self.AIM["verify"] is None:
                    self.AIM["verify"]  = getattr(self, "PVWA_CA", False)

                # Integer conversion
                self.AIM["timeout"] = int(self.AIM["timeout"])
                self.AIM["max_concurrent_tasks"] = int(self.AIM["max_concurrent_tasks"])
            else:
                self.AIM = None

            self.CPM            = document_check["CPM"]
            self.retention      = int(document_check["retention"])
            self.customIPField  = document_check["customIPField"]

        except AttributeError as e:
            raise ValueError(f"Malformed configuration file : {str(e)}")


    def _check_yaml(self, yaml_dict: dict, yaml_name: str, attrname_definition, dict_name: dict = None, raise_unknown_attr=False):
        """_check_yaml - Read a YAML section and initialize variable

        Initialize dict_name if define from Yaml
            otherwise set self attributes

        Arguments:
            yaml_dict {dict}            Yaml section definition
            yaml_name {str}             Name of the Yaml section
            attrname_definition {dict}  Section attribut defintion

        Keyword Arguments:
            dict_name {dict}            Dictionary return value, if None self is set
            raise_unknown_attr          Raise a error for a unknown attribute

        Raises:
            KeyError: Mutually exclusive parameters
            KeyError: Unknown attribut name in section
        """
        multiple_name={}

        # Set the default value of all attributes
        for k, attr_def in attrname_definition.items():
            if dict_name is None:
                setattr(self, attr_def.attrName, attr_def.defaultValue)
            else:
                dict_name[attr_def.attrName] = attr_def.defaultValue

            # setup multiple name validation
            if attr_def.multipleName_ind:
                if attr_def.attrName not in multiple_name:
                    multiple_name[attr_def.attrName] = [k]
                else:
                    multiple_name[attr_def.attrName].append(k)

        if yaml_dict is None:
            return

        # Read Yaml
        for k in list(yaml_dict.keys()):
            keyname = k.lower()
            attr_def = attrname_definition.get(keyname, None)

            if attr_def is None:
                if raise_unknown_attr:
                    raise KeyError(f"aiobastion configuration file error: Unknown attribut '{k}' in section '{yaml_name}': {k}={yaml_dict[k]!r}")
                else:
                    # Print error in stderr, and let the user handle the error
                    print(f"Warning - aiobastion configuration file error: Unknown attribut '{k}' in section '{yaml_name}': {k}={yaml_dict[k]!r}", file=sys.stderr)
                    continue

            if k != keyname:
                yaml_dict[keyname] = yaml_dict.pop(k)

            if dict_name is None:
                setattr(self, attr_def.attrName, yaml_dict[keyname])
            else:
                dict_name[attr_def.attrName] = yaml_dict[keyname]


        # Check if multiple names have been define more that once
        if multiple_name:
            for exclusive_list in multiple_name.values():
                count = 0
                for name in exclusive_list:
                    if name in yaml_dict:
                        count += 1

                if count > 1:
                    raise KeyError(f"Configuration file error: Mutually exclusive parameters: {exclusive_list!r} in '{yaml_name}' section")



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
