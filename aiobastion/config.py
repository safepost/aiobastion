# -*- coding: utf-8 -*-

import yaml
import warnings
from .exceptions import AiobastionConfigurationException

class Config:
    """ Config   Transform input information from configuration file or serialization to the different modules.

        account, accountgroup, aim, applications, cyberark, group, platform, safe, sessionmanagement, systemhealth, user, utilities.
    """
    # Because of a conflict with EPV definition at intialization for AIOBASTION
    # The following default values are defined here (instead of EPV class)
    CYBERARK_DEFAULT_KEEP_COOKIES = False
    CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS = 10
    # CYBERARK_DEFAULT_RETENTION = 10
    CYBERARK_DEFAULT_TIMEOUT = 30
    CYBERARK_DEFAULT_VERIFY = True
    CYBERARK_OPTIONS_MODULES_LIST = [
        "account",
        "accountgroup",
        "aim",
        "applications",
        "cyberark",
        "group",
        "platform",
        "safe",
        "sessionmanagement",
        "systemhealth",
        "user",
        "utilities",
    ]

    # List of EPV attributes from serialization
    _EPV_SERIALIZED_FIELDS_IN = [
        "api_host",                 # synomym of api_host: host
        "authtype",
        "keep_cookies",
        "max_concurrent_tasks",     # synomym of max_concurrent_tasks: masktasks
        "password",
        "timeout",
        "token",                    # in serializattion only (changed to __token)
        "user_search",
        "username",
        "verify",
    ]


    def __init__(self, configfile: str = None, label: str=None, custom: dict=None, serialized=None, token=None):
        """Parse the config file or the serialization and populate the options_modules (account, aim, cyberark, safe, ...).

        The EPV class will call the appropriate class (module) for initialization and validation
        using options_modules.  Serialization will use the same functionality.
            ex: Account._init_validate_class_attributes(self.options_modules["account"])
        """

        # Class definition
        self.configfile = configfile
        self.custom = custom
        self.label = label

        if label is None and serialized:
            self.label = "serialized"

        if not configfile and not serialized:
            raise AiobastionConfigurationException("Internal error: no configfile and no serialized")


        self.options_modules = {}

        # Define a dictionary for every options module (aim, account, cyberark, safe ...)
        for keyname in Config.CYBERARK_OPTIONS_MODULES_LIST:
            self.options_modules[keyname] = {}

        if token is not None:
            self.options_modules["cyberark"]["token"] = token


        if configfile:
            self._mngt_configfile()
        elif serialized:
            self._mngt_serialized(serialized)


    def _mngt_configfile(self):
        """ _mngt_configfile    management of the configuration file

        Cross reference between the configuration file and the Config class attributes (for information)

        Yaml Configuration file                         Config class
        --------------------------------------          ------------------------------------------------
        Section         Attribute                       Attribute                               Dictonnary key
        -------------- ------------------------         ---------------                         --------------
        label                                           label
        custom          <all>                           custom {dict}
                                                        configfile

        connection(1)   appid                           options_modules["aim"]                  appid

        connection      authtype                        options_modules["cyberark"]             authtype
        connection      password                        options_modules["cyberark"]             password
        connection      user_search                     options_modules["cyberark"]             user_search {dict}
        connection      username                        options_modules["cyberark"]             username

        pvwa            host                            options_modules["cyberark"]             api_host
        pvwa            timeout                         options_modules["cyberark"]             timeout {int}
        pvwa(1)         max_concurrent_tasks            options_modules["cyberark"]             max_concurrent_tasks {int}
        pvwa(1)         maxtasks                        options_modules["cyberark"]             max_concurrent_tasks {int}
        pvwa            keep_cookies                    options_modules["cyberark"]             keep_cookies {bool}
        pvwa(1)         ca                              options_modules["cyberark"]             verify Union[{bool}, {str}]
        pvwa(1)         verify                          options_modules["cyberark"]             verify Union[{bool}, {str}]

        cpm(2)                                          options_modules["account"]              cpm
        retention(2)                                    options_modules["account"]              retention {int}


        *** aim module ***
        aim(1)              appid                       options_modules["aim"]                  appid
        aim                 cert                        options_modules["aim"]                  cert
        aim                 host                        options_modules["aim"]                  host
        aim                 key                         options_modules["aim"]                  key

        aim                 passphrase                  options_modules["aim"]                  passphrase
        aim                 timeout                     options_modules["aim"]                  timeout {int}

        aim(1)              max_concurrent_tasks        options_modules["aim"]                  max_concurrent_tasks {int}

        aim(1)              verify                      options_modules["aim"]                  verify Union[{bool}, {str}]

        custom(3)           LOGON_ACCOUNT_INDEX         options_modules["safe"]                 logon_account_index {int}
        custom(3)           RECONCILE_ACCOUNT_INDEX     options_modules["safe"]                 reconcile_account_index {int}


        *** modules (4) ***
        account(3)          logon_account_index         options_modules["account"]              logon_account_index {int}
        account(3)          reconcile_account_index     options_modules["account"]              reconcile_account_index {int}

        safe                cpm                         options_modules["safe"]                 cpm
        safe                retention                   options_modules["safe"]                 retention {int}


        accountgroup        <all>                       options_modules["accountgroup"]         <all>
        applications         <all>                      options_modules["applications"]         <all>
        group               <all>                       options_modules["group"]                <all>
        platform            <all>                       options_modules["platform"]             <all>
        sessionmanagement   <all>                       options_modules["sessionmanagement"]    <all>
        systemhealth        <all>                       options_modules["systemhealth"]         <all>
        user                <all>                       options_modules["user"]                 <all>
        utilities           <all>                       options_modules["utilities"]            <all>
        ...

        (1)     Synonyms
        (2)     Move from Global section to save modules
        (3)     Move from custom to safe section    (issue a warning)
        (4)     All modules will be initialized and validated their own attributes.
                This will be done in the EPV class with <class>._init_validate_class_attributes.

        """
        with open(self.configfile, 'r') as config:
            configuration = yaml.safe_load(config)

        # Translate keys of dictionary and sub-directories in lowercase
        # Do not modified the sub-key dictionary of the 'custom' section.
        configuration = Config._serialized_dict_lowercase_key(configuration, "", self.configfile)

        global_sections = [
            "connection",               # options modules: aim and cyberark
            "cpm",                      # deprecated, move to safe section
            "label",                    # Config.label
            "pvwa",                     # options modules: cyberark
            "retention",                # deprecated, move to safe section
            "custom",                   # Config.custom: Customer use only (not aiobastion)

            # "customipfield"           # Remove from configuration file
            ] + Config.CYBERARK_OPTIONS_MODULES_LIST


        # Check the global section defined in the configuration file
        for k in configuration.keys():
            if k not in global_sections:
                raise AiobastionConfigurationException(f"Unknown attribute '{k}' in {self.configfile}")

        # --------------------------------------------
        # Config attribute class
        # --------------------------------------------
        if "label" in configuration:
            self.label = configuration["label"]

        if "custom" in configuration:
            self.custom = configuration["custom"]

        # --------------------------------------------
        # cyberark: connection and pvwa
        # --------------------------------------------
        if "connection" in configuration and configuration["connection"]:
            for k, v in configuration["connection"].items():
                if k == "appid":
                    self._add_key_to_options_modules("aim", k, v, self.configfile)
                else:
                    self._add_key_to_options_modules("cyberark", k, v, self.configfile)


        if "pvwa" in configuration and configuration["pvwa"]:
            self._add_dict_to_options_modules("cyberark", configuration["pvwa"], self.configfile)

        # if "customipfield" in configuration:
        #     self.customIPField = configuration["customipfield"]

        # --------------------------------------------
        # options modules (account, aim, ...)
        # --------------------------------------------
        for keyname in Config.CYBERARK_OPTIONS_MODULES_LIST:
            if keyname in configuration and configuration[keyname]:
                if keyname in ["safe", "aim"]:
                    self._add_dict_to_options_modules(keyname, configuration[keyname], self.configfile)
                else:
                    self.options_modules[keyname] = configuration[keyname]

        # --------------------------------------------
        # Compatilibility and exceptions
        # --------------------------------------------
        # Don't allow 'safe' and ('cpm' or 'retention').
        if "cpm" in configuration or "retention" in configuration:
            if "safe" in configuration:
                raise AiobastionConfigurationException(f"Duplicate definition: Move 'cpm' and 'retention' to the 'safe' definition in {self.configfile}.")
            else:
                warnings.warn(
                            "aiobastion - Please, move 'cpm' and "
                            "'retention' definition from global to 'safe' "
                            f"section in {self.configfile}.")

        # Move 'cpm' and 'retention' to 'safe' module
        for keyname in ["cpm", "retention"]:
            if keyname in configuration:
                self._add_key_to_options_modules("safe", keyname, configuration[keyname], self.configfile)

        # Don't allow 'account' and (custom['logon_account_index'] or custom['reconcile_account_index']).
        self._mng_account_custom_definition(self.configfile)

    def _mngt_serialized(self, serialized):
        """_mngt_serialized    management of the serialized defintion

        Cross reference between the configuration file and the Config class attributes (for information)

        Yaml Configuration file                     Config class
        --------------------------------------      ------------------------------------------------
        Serialized      Attribute                   Attribute                       Dictonnary key
        --------------  ------------------------    ---------------                 --------------
        label                                       label
        custom          <all>                       custom {dict}                   <all>
                                                    configfile = None

        api_host                                    options_modules["cyberark"]     api_host
        authtype                                    options_modules["cyberark"]     authtype
        keep_cookies                                options_modules["cyberark"]     keep_cookies         {bool}
        max_concurrent_tasks                        options_modules["cyberark"]     max_concurrent_tasks {int}
        password                                    options_modules["cyberark"]     password
        timeout                                     options_modules["cyberark"]     timeout {int}
        token                                       options_modules["cyberark"]     token
        user_search                                 options_modules["cyberark"]     user_search          {dict}
        username                                    options_modules["cyberark"]     username
        verify                                      options_modules["cyberark"]     verify Union         [{bool}, {str}]

        cpm(2)                                      options_modules["account"]      cpm
        retention(2)                                options_modules["account"]      retention {int}

        custom(3)       LOGON_ACCOUNT_INDEX         options_modules["account"]      logon_account_index {int}
        custom(3)       RECONCILE_ACCOUNT_INDEX     options_modules["account"]      reconcile_account_index {int}


        ***  modules (4) ***
        account             <all>                   options_modules["account"]              <all>
        accountgroup        <all>                   options_modules["accountgroup"]         <all>
        aim                 <all>                   options_modules["aim"]                  <all>
        applications        <all>                   options_modules["applications"]         <all>
        group               <all>                   options_modules["group"]                <all>
        platform            <all>                   options_modules["platform"]             <all>
        safe                <all>                   options_modules["safe"]                 <all>
        sessionmanagement   <all>                   options_modules["sessionmanagement"]    <all>
        systemhealth        <all>                   options_modules["systemhealth"]         <all>
        user                <all>                   options_modules["user"]                 <all>
        utilities           <all>                   options_modules["utilities"]            <all>

        ...

        (1)     Synonyms
        (2)     Move to save modules
        (3)     Move from custom to account module    (issue a warning)
        (4)     All modules will be initialized and validated their own attributes.
                This will be done in the EPV class with <class>._init_validate_class_attributes.

        Raises:
            AiobastionConfigurationException:
                Type error: Parameter 'serialized' must be a dictionary.
                Move 'cpm' and 'retention' to the 'safe' definition in serialization.
                Duplicate 'aim' definition in seralized. Specify only 'aim' and remove 'AIM'.
                Unknown attribute '{k}' in serialization:
        """

        if not isinstance(serialized, dict):
            raise AiobastionConfigurationException("Type error: Parameter 'serialized' must be a dictionary.")

        # Translate keys of dictionary and sub-directories in lowercase
        # Do not modified the sub-key dictionary of the 'custom' section.
        serialized = Config._serialized_dict_lowercase_key(serialized, "", "serialized")

        # Don't allow 'safe' and ('cpm' or 'retention').
        if "safe" in serialized and \
           ("cpm" in serialized or "retention" in serialized):
            raise AiobastionConfigurationException("Duplicate definition: Move 'cpm' and 'retention' to the 'safe' definition in serialization.")

        # Validate dictionary keys
        for k, v in serialized.items():
            # cyberark definition
            if k in Config._EPV_SERIALIZED_FIELDS_IN:
                # Initialize cyberark attribut
                self._add_key_to_options_modules("cyberark", k, v, "serialized")

            elif k in Config.CYBERARK_OPTIONS_MODULES_LIST:
                # Keep options modules definition for later (account, aim, safe)
                self.options_modules[k] = v

            elif k == "cpm" or k == "retention":
                # Initialize Safe attribut for comptibility
                self._add_key_to_options_modules("safe", k, v, "serialized")

            elif k == "custom":
                self.custom = v
            else:
                raise AiobastionConfigurationException(
                    f"Unknown attribute '{k}' in serialization: {serialized[k]!r}")

        # Don't allow 'account' and (custom['logon_account_index'] or custom['reconcile_account_index']).
        self._mng_account_custom_definition("serialized")


    def _add_dict_to_options_modules(self, module: str, configuration: dict, configfile: str):
        if configuration is None:
            return

        for k, v in configuration.items():
            if k in self.options_modules[module] and \
               v != self.options_modules[module][k]:
                # Raise an error only want values are different.
                raise AiobastionConfigurationException(f"Duplicate key '{module}/{k}'"
                                                       f" in {configfile}.")

            self.options_modules[module][k] = v

    def _add_key_to_options_modules(self, module: str, keyname: str, value, configfile: str):
        if value is None:
            return

        if keyname in self.options_modules[module] and \
            value != self.options_modules[module][keyname]:
            # Raise an error only when values are different.
            raise AiobastionConfigurationException(f"Duplicate key '{module}/{keyname}'"
                                                    f" in {configfile}.")

        self.options_modules[module][keyname] = value



    def _mng_account_custom_definition(self, configfile: str):
        # Don't allow 'account' and (custom['logon_account_index'] or custom['reconcile_account_index']).
        if self.custom and isinstance(self.custom, dict):
            keyname_list = []

            custom_warning_ind = True

            # Are logon_account_index or reconcile_account_index keys exist ?
            for k in self.custom.keys():
                keyname = k.lower()

                if keyname in ["logon_account_index", "reconcile_account_index"]:
                    keyname_list.append(k)

                    if custom_warning_ind:
                        custom_warning_ind = False
                        warnings.warn(
                            "aiobastion - Please, move 'logon_account_index' and "
                            "'reconcile_account_index' definition from 'custom' to 'account' "
                            f"section in {configfile}.")


            if keyname_list:
                # Don't allow 'account' and 'custom'.
                if self.options_modules["account"]:
                    raise AiobastionConfigurationException(
                        "Duplicate definition: move 'logon_account_index' and "
                        "'reconcile_account_index' from 'custom' to 'account' section in {configfile}.")
                else:
                    # Move 'logon_account_index' and 'reconcile_account_index' to 'account' options modules
                    #   and remove it from custom
                    new_custom = {}

                    for k, v in self.custom.items():
                        if k in keyname_list:
                            self.options_modules["account"][k.lower()] = v
                        else:
                            new_custom[k] = v

                    if new_custom:
                        self.custom = new_custom
                    else:
                        self.custom = None


    @staticmethod
    def _serialized_dict_lowercase_key(src: dict, section_name: str, configfile: str):
        """_serialized_dict_lowercase_key  Translate keys of dictionary and sub-dictionaries in lowercase

        Do not modified the sub-key dictionary of the 'custom' section.

        Arguments:
            src {dict}              Source dictionary
            section_name {str}      Error message section name
            configfile {str}        Error message source name

        Raises:
            AiobastionConfigurationException: _description_
            AiobastionConfigurationException: _description_

        Returns:
            _type_ -- _description_
        """
        if not isinstance(src, dict):
            raise AiobastionConfigurationException(
                f"Invalid dictionary type '{section_name}' in {configfile}")

        rt = {}
        for k, v in src.items():
            keyname = k.lower()

            if keyname in rt:
                raise AiobastionConfigurationException(f"Duplicate key '{section_name}/{keyname}'"
                                                        f" in {configfile}")

            if isinstance(v, dict) and  keyname != "custom":
                rt[keyname] = Config._serialized_dict_lowercase_key(v, f"{section_name}/{keyname}", configfile)
            else:
                rt[keyname] = v

        return rt



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


def validate_integer(configfile: str, section_name: str, val) -> int:
    try:
        v = int(val)
    except (ValueError, TypeError):
        raise AiobastionConfigurationException(f"Invalid integer value '{section_name}'"
                                                f" in {configfile}: {val!r}")

    return v

def validate_bool(configfile: str, section_name: str, val) -> bool:
    if isinstance(val, bool):
        rt = val
    else:
        raise AiobastionConfigurationException(f"Invalid boolean value '{section_name}'"
                                                f" in {configfile}: {val!r}")

    return rt

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
        if isinstance(i,list):
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
