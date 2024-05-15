"""
test_config_value.py

This is a exhaustive test of the Config and EPV class initialization.
It does not access CyberArk.
For debugging purpose, this test generates a lot of trace in the 'aiobastion_test' logger define in setUpClass.

test 0#  Check value complete base test
    test 01:    Check value return from config Class from the YAML complete base test
    test 02:    Check value return from EPV Class from the YAML complete base test
    test 03:    Check value return from EPV Class from the serialization complete base test

test 1#  Check mixed case key attribute (Uppercase and mixed case)
    test 11:    Check value return from EPV Class from a the YAML file
    test 12:    Check value return from EPV Class from a the serialization

test 2#  Check default initialization
    test 21:    Check value return from EPV Class from a tiny YAML file
    test 22:    Check value return from EPV Class from a tiny serialization

test 3#  Check synomym field usage
    test 31:    Check value return from EPV Class from a YAML file
    test 32:    Check value return from EPV Class from a serialization

test 4#  Check error message for all unknown field in section
    test 41:    Check error message from EPV Class from a tiny YAML file
    test 41:    Check error message from EPV Class from a tiny serialization

test 5#  Check error message for all synomym duplicate field usage
    test 51:    Check error message from EPV Class from a tiny YAML file
    test 51:    Check error message from EPV Class from a tiny serialization

test 6#  Check error message for all invalid type check
    test 61:    Check error message from EPV Class from a tiny YAML file
    test 61:    Check error message from EPV Class from a tiny serialization

test 7#  Check error message for all invalid account value check
    test 71:    Check error message from EPV Class from a tiny YAML file
                Check error message from EPV Class from a tiny serialization

test 8#  Check error message for EPV call with no parameter
    test 81:    Check error message from EPV Class

test 9# Check value return from EPV.to_json function
    test 71:    Check value return from EPV.to_json function from the serialization complete base test

The base YAML file come from ./tests/test_data/custom_config.yml
    - This file will not be used to access CyberArk.
    - All field must be define without any error and no synonyms.
    - Key attribute must be in lowercase.

"""
import os
import copy
import yaml
import unittest
from unittest import IsolatedAsyncioTestCase
import aiobastion
# import tests
from aiobastion import CyberarkException
from typing import Optional
import tempfile
import datetime
import pprint
import logging
import inspect


# -----------------------------------
# constants
# -----------------------------------
MODULE_DIRNAME = os.path.dirname(__file__)
MODULE_NAME = os.path.basename(__file__)
HEADERLINE = "---------------------------------------------"
# HEADER = f"\n\n# {HEADERLINE}\n# %s\n# {HEADERLINE}\n"
HEADER = f"# %s (start)"

UNDEFINED_VALUE = "?? unknown ??"
EPV_ATTRIBUTE_NAME = [
    # CyberArk attributes
    "api_host",
    "authtype",
    "keep_cookies",
    "max_concurrent_tasks",
    "password",
    "timeout",
    "user_search",
    "username",
    "verify",

    # CyberArk configuration file
    "config",

    # CyberArk internal attributes
    "cookies",
    "logger",
    "request_params",
    "session",
    "user_list",

    # CyberArk modules
    "AIM",
    "account",
    "accountgroup",
    "application",
    "group",
    "platform",
    "safe",
    "session_management",
    "system_health",
    "user",
    "utils",

    # "__sema"
    # "__token"
]

# -----------------------------------
# Class Definition
# -----------------------------------
class TestConfig_epv(unittest.TestCase):
    """TestConfig_epv - Check EPV initialization """
    logger = None
    pprint = pprint.PrettyPrinter(indent=3, width=120, depth=5)

    yaml_dict = None                # load yaml dictionary  (may generate a new yaml)
    serialize_dict = None           # serialization dictionary from loaded yaml dict.
    epv_validation_dict = None     # EPV Validation definition (adjust from serialize_dict)

    yaml_filename  = os.path.join(MODULE_DIRNAME, "test_data", "custom_config.yml")
    yaml_temp_name = os.path.join(tempfile.gettempdir(), f"{MODULE_NAME}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}{os.getppid()}.yml")

    @classmethod
    def setUpClass(cls):
        """
        setUpClass - initialization of class test.

           1) Create the YAML dictionary variable (cls.yaml_dict variable)
                from the file  ./test/custom_config.yml
                    This YAML file define all possible fields in every section
                        - without any error,
                        - no synonyms and
                        - keys must be define in lowercases (including "aim").
                Usage: Base definiton to recreate YAML file test

            2) Create the serialization variable (cls.serialize_dict)
                from the YAML dictionary (cls.yaml_dict)
                Usage: Base definiton to recreate serialization test

            3) Create the EPV validation value variable (cls.epv_validation_dict)
                from the serialization variable (cls.serialize_dict)
                Usage: Base definiton to validate return value
        """
        fnc_name = inspect.currentframe().f_code.co_name

        # Setup logger if needed
        logger = logging.getLogger("aiobastion_test")

        # Is logger define ?
        if not logger.hasHandlers():
            logging_name = os.path.join(tempfile.gettempdir(), f"{MODULE_NAME}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}_{os.getppid()}.trc")
            print(f"\n\nTrace file:        '{logging_name}'\n")

            logger.setLevel(logging.DEBUG)
            fh = logging.FileHandler(logging_name)
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s %(module)20s %(funcName)45s %(lineno)5d: %(message)s')
            fh.setFormatter(formatter)
            logger.addHandler(fh)

            cls.logger = logger
            cls.writelog(f"Trace file:        '{logging_name}'")


        cls.writelog(HEADER, fnc_name)
        cls.writelog(f"yaml_filename:     '{cls.yaml_filename}'")
        cls.writelog(f"yaml_temp_name:    '{cls.yaml_temp_name}'")

        # Import the complete yaml configuration file
        #   All field define without any error and no synonyms
        #
        # This dictonary will be the main source of testing

        with open(cls.yaml_filename, "r") as file:
            cls.yaml_dict = yaml.safe_load(file)

        # Convert all global section and attribute in lowercase (except AIM section) (3 levels)
        for section_name in list(cls.yaml_dict.keys()):
            section_name_new = section_name.lower()

            if section_name_new == "aim":
                section_name_new = "AIM"

            if section_name != section_name_new:
                cls.yaml_dict[section_name_new] =  cls.yaml_dict.pop(section_name)

            # Lowercase first level
            if section_name != "custom" and isinstance(cls.yaml_dict[section_name_new], dict):
                for attrName1 in list(cls.yaml_dict[section_name_new].keys()):
                    attrName1_new = attrName1.lower()

                    if attrName1 != attrName1_new:
                        cls.yaml_dict[section_name_new][attrName1_new] = cls.yaml_dict[section_name_new].pop(attrName1)

                    # Lowercase second level
                    if isinstance(cls.yaml_dict[section_name_new][attrName1_new], dict):
                        for attrName2 in list(cls.yaml_dict[section_name_new][attrName1_new].keys()):
                            attrName2_new = attrName2.lower()

                            if attrName2 != attrName2_new:
                                cls.yaml_dict[section_name_new][attrName1_new][attrName2_new] = cls.yaml_dict[section_name_new][attrName1_new].pop(attrName2)

                        # Lowercase third level
                        if isinstance(cls.yaml_dict[section_name_new][attrName1_new][attrName2_new], dict):
                            for attrName3 in list(cls.yaml_dict[section_name_new][attrName1_new][attrName2_new].keys()):
                                attrName3_new = attrName3.lower()

                                if attrName3 != attrName3_new:
                                    cls.yaml_dict[section_name_new][attrName1_new][attrName2_new][attrName3_new] = \
                                        cls.yaml_dict[section_name_new][attrName1_new][attrName2_new].pop(attrName3)


        cls.write_pprint("cls.yaml_dict (global definition)", cls.yaml_dict)

        # Format to serialization (restructure from yaml)
        cls.serialize_dict = copy.deepcopy(cls.yaml_dict)

        if "label" in cls.serialize_dict:
            del cls.serialize_dict["label"]

        for section_name in list(cls.serialize_dict.keys()):
            section_name_new = section_name.lower()

            if section_name_new not in aiobastion.config.Config.CYBERARK_OPTIONS_MODULES_LIST + [
                "pvwa",
                "connection",
                "custom",
                ]:
                raise KeyError(f"Unexpected configuration file global section: {section_name}")

            # # convert section in lowercase except AIM
            # if section_name_new == "aim":
            #    section_name_new = "AIM"
            #
            #     if  section_name == "aim":
            #         cls.serialize_dict[section_name_new] = cls.serialize_dict.pop(section_name)

            # elif section_name != section_name_new:
            #     cls.serialize_dict[section_name_new] = cls.serialize_dict.pop(section_name)

            if "connection" == section_name:
                for k in list(cls.serialize_dict["connection"].keys()):
                    if k == "appid":
                        if "AIM" not in cls.serialize_dict:
                            cls.serialize_dict["AIM"] = {}

                        cls.serialize_dict["AIM"][k] = cls.serialize_dict["connection"][k]
                    else:
                        cls.serialize_dict[k] = cls.serialize_dict["connection"][k]

                del cls.serialize_dict["connection"]

            elif "pvwa" == section_name_new:
                for k in list(cls.serialize_dict[section_name_new].keys()):
                    if k == "host":
                        k_new = "api_host"
                    else:
                        k_new = k

                    cls.serialize_dict[k_new] = cls.serialize_dict["pvwa"][k]

                del cls.serialize_dict["pvwa"]


        cls.write_pprint("cls.serialize_dict (global definition)", cls.serialize_dict)

        # Adjust config.custom definition
        cls.epv_validation_dict = copy.deepcopy(cls.serialize_dict)
        cls.epv_validation_dict["config"] = {
            "custom": cls.epv_validation_dict.pop("custom"),
            "label": cls.yaml_dict["label"],
            "configfile": cls.yaml_temp_name
            }

        # Debug check_section_value
        #   - Test different value
        # cls.epv_validation_dict["api_host"] = "ServerName"

        cls.write_pprint("cls.epv_validation_dict (global definition)", cls.epv_validation_dict)


    @classmethod
    def TearDown(cls):
        """TearDown - cleanup of class test """
        cls.writelog(HEADER, "TearDown")

        if os.path.exists(TestConfig_epv.yaml_temp_name):
            os.remove(TestConfig_epv.yaml_temp_name)

    @classmethod
    def writelog(cls, *args, **kwargs):
        """writelog - Write multiple line to logger"""

        if cls.logger:
            stacklevel = kwargs.pop("stacklevel", 1) + 1

            if len(args) == 1:
                lines = args[0]
            else:
                lines = args[0] % args[1:]

            for line in lines.split('\n'):
                cls.logger.debug(line, stacklevel=stacklevel, **kwargs)

    @classmethod
    def write_pprint(cls, title: str, d: dict, **kwargs):
        """write_pprint - Write a prettyprint dictionary to logger"""
        stacklevel = kwargs.pop("stacklevel", 1) + 1

        cls.writelog(f" {title} " .center(100, "-"), stacklevel=stacklevel, **kwargs)
        cls.writelog(cls.pprint.pformat(d), stacklevel=stacklevel, **kwargs)
        cls.writelog(f" {title} (end) " .center(100, "-"), stacklevel=stacklevel, **kwargs)

    @classmethod
    def write_file(cls, filename: str, title=None, **kwargs):
        """write_file - Write file content to logger"""
        stacklevel = kwargs.pop("stacklevel", 1) + 1

        if title is None:
            title = filename

        cls.writelog(f" {title} ".center(100, "-"), stacklevel=stacklevel, **kwargs)

        with open(filename, "r") as fd:
            cls.writelog(fd.read(), stacklevel=stacklevel, **kwargs)

        cls.writelog(f" {title} (end) " .center(100, "-"), stacklevel=stacklevel, **kwargs)


    @classmethod
    def write_EPV(cls, title, epv_env: aiobastion.EPV, **kwargs):
        """write_EPV - Write EPV class attribute to logger"""
        stacklevel = kwargs.pop("stacklevel", 1) + 1
        # kwargs.setdefault("stacklevel", 3)

        d= {}

        for k in vars(epv_env):
            # Is it a class ?
            if k in [
                "AIM",
                "account",
                "accountgroup",
                "application",
                "config",
                "group",
                "logger"
                "platform",
                "safe",
                "session_management",
                "system_health",
                "user",
                "utils",
                ]:
                d[k] = vars(getattr(epv_env, k, None))
            else:
                d[k] = getattr(epv_env, k)

        cls.write_pprint(title, d, stacklevel=stacklevel, **kwargs)


    def call_EPV(self, title: str, /, configFile: str = None, yaml_dict: Optional[dict] = None, serialized: Optional[dict] = None,
                 trace_input: bool = False, trace_epv: bool = False, trace_check: bool = False, raise_condition = False,
                 expected_value: Optional[dict] = None, **kwargs):
        """call_EPV

        1) if yaml_dict, create a yaml file from yaml_dict
        2) Display input definition (Yaml file or serialized) if aksed
        3) call EPV(...)
        4) if raise_condition expected and condition has not been raised
            4.1) Display input definition (Yaml file or serialized)
        5) Display EPV instance class return if asked


        Args:
            title (str):    Test name

        Optional Args:
            configFile (str, optional):                 Name of a Yaml file
            yaml_dict (Optional[dict], optional):       Yaml dictionary use to create Yaml file
            serialized (Optional[dict], optional):      serialized dictionary
            trace_input (bool, optional):               Display input parameters (Yaml file or serialized) ?
            trace_epv (bool, optional):                 Display EPV instance definition returned ?
            trace_check (bool, optional):               Display check value trace ?
            raise_conditon (bool, optional):            Will it raise a error ?
            expected_value (Optional[dict], optional):  Expected value Dictionary


        Returns:
            _type_: _description_
        """
        stacklevel = kwargs.pop("stacklevel", 1) + 1

        try:
            if configFile or yaml_dict:
                if configFile:
                    fileName = configFile
                else:   # yaml_dict
                    fileName = TestConfig_epv.yaml_temp_name

                    # Write the configuration file
                    with open(TestConfig_epv.yaml_temp_name, "w") as tmp_fd:
                        configuration = yaml.dump(yaml_dict, tmp_fd)

                if trace_input:
                    self.write_file(fileName, title=f"{title} - Yaml", stacklevel=stacklevel, **kwargs)

                if expected_value and \
                        "config" in expected_value and \
                       "configfile" in expected_value["config"]:
                    expected_value["config"]["configfile"] = fileName

                epv_env = aiobastion.EPV(configfile=fileName)
            else: # serialized
                if trace_input:
                    self.write_pprint(f"{title} - serialization", serialized, stacklevel=stacklevel, **kwargs)

                epv_env = aiobastion.EPV(serialized=serialized)
        except Exception as err:
            self.writelog(f"{title}: raise {err}", stacklevel=stacklevel, **kwargs)
            raise err


        if raise_condition:
            # Raise condition has not been raised, display input information if not already done.
            if not trace_input:
                self.writelog(f"{title}: raise *** Test not raise ***", stacklevel=stacklevel, **kwargs)

                if configFile or yaml_dict:
                    self.write_file(fileName, title=f"{title} - Yaml", stacklevel=stacklevel, **kwargs)
                else:   # serialized
                    self.write_pprint(f"{title} - serialization", serialized, stacklevel=stacklevel, **kwargs)

        if trace_epv or raise_condition:
            self.write_EPV(f"{title} - EPV", epv_env, stacklevel=stacklevel, **kwargs)

        if expected_value:
            self.check_epv_value_with_dict(f"{title} - check value", epv_env, expected_value, trace_check=trace_check, stacklevel=stacklevel, **kwargs)

        return epv_env


    def check_section_value(self, testname: str, obj, expected_value: dict, trace_check: bool = False, **kwargs):
        """ check_section_value - Verify if expected values are defined """
        stacklevel = kwargs.pop("stacklevel", 1) + 1

        # self.writelog(f"{testname} debug obj({type(obj)})  expected_value({type(expected_value)})", stacklevel=stacklevel, **kwargs)

        if expected_value is None:
            if trace_check:
                self.writelog(f"{testname} skip test: expected_value is None; %r", obj, stacklevel=stacklevel, **kwargs)

            # self.assertIsNone(obj, msg=f"{testname}: value not None.")

        else:
            if isinstance(expected_value, dict) and isinstance(obj, dict):
                for k, ev in expected_value.items():
                    v = obj.get(k, UNDEFINED_VALUE)   # custom
                    # self.writelog(f"{testname} debug dict '{k}' obj({v!r})  expected_value({ev!r})", stacklevel=stacklevel, **kwargs)

                    with self.subTest(attrName=f"{testname}/{k}"):
                        self.check_section_value(f"{testname}/{k}", v, ev, trace_check=trace_check, stacklevel=stacklevel, **kwargs)
            elif isinstance(expected_value, dict):
                # We assume it is a class
                for k, ev in expected_value.items():
                    # keyname = k.lower()
                    with self.subTest(attrName=f"{testname}/{k}"):
                        v = getattr(obj, k, None)
                        self.check_section_value(f"{testname}/{k}", v, ev, trace_check=trace_check, stacklevel=stacklevel, **kwargs)
            else:
                if trace_check:
                    self.writelog(f"{testname} check - {obj} == {expected_value}", stacklevel=stacklevel, **kwargs)

                with self.subTest(testname=testname):
                    self.assertIsInstance(obj, type(expected_value), msg=f"{testname}: type error expecting a {type(expected_value)}")
                    self.assertEqual(obj, expected_value, msg=f"{testname}: value error {expected_value!r}")




    def check_epv_value_with_dict(self, testname: str, epv_env: aiobastion.EPV, expected_value: dict, trace_check: bool = False, **kwargs):
        """ check_epv_value_with_dict - Verify expected values
            This verification is driven by the dictionary "expected_value".

            It does not verify EPV.config
        """
        kwargs.setdefault("stacklevel", 1)
        kwargs["stacklevel"] += 1

        # check every field
        self.assertIsInstance(epv_env, aiobastion.EPV, msg=f"""{testname}: Wrong epv_env type""")

        if trace_check:
            self.writelog(testname .center(100, "-"), **kwargs)

        # Check all expected value
        self.check_section_value(testname, epv_env, expected_value, trace_check=trace_check, **kwargs)

        if trace_check:
            self.writelog(testname.center(100, "-"), **kwargs)

        return



    def test_01_Config_complete_yml(self):
        """ test_01_Config_complete_yml  - Test Config instance class (yaml file)
            Check all fields in Config instance class return.
        """
        fnc_name = inspect.currentframe().f_code.co_name

        self.writelog(HEADER, fnc_name)

        TestConfig_epv.write_file(TestConfig_epv.yaml_filename, f"{fnc_name} - original Yaml file")
        config_instance = aiobastion.config.Config(configfile=TestConfig_epv.yaml_filename)

        # check every field
        self.assertIsInstance(config_instance, aiobastion.config.Config, msg=f"""("test_data/custom_config.yml") in error""")

        # Config class
        self.assertEqual(config_instance.label, TestConfig_epv.yaml_dict["label"], msg="Label value error")
        self.assertEqual(config_instance.configfile, TestConfig_epv.yaml_filename, msg="configfile value error")
        self.assertIsNotNone(config_instance.custom, msg="custom section not define")

        for sectionName in config_instance.options_modules.keys():
            with self.subTest(section=sectionName):
                self.assertIn(sectionName, aiobastion.config.Config.CYBERARK_OPTIONS_MODULES_LIST,
                            msg=f"{sectionName} Unknowed section '{sectionName}' in options_modules.")

                if sectionName == "cyberark":
                    # Connection
                    for attrName in ["authtype", "password", "user_search", "username"]:
                        self.assertIn(attrName, config_instance.options_modules[sectionName],
                                      msg=f"{attrName} not define in options_modules[{sectionName}]")
                        self.assertEqual(config_instance.options_modules[sectionName][attrName], TestConfig_epv.yaml_dict["connection"][attrName],
                                        msg=f"""Invalid value in options_modules[{sectionName}][{attrName}]. Expected: {TestConfig_epv.yaml_dict["connection"][attrName]!r}""")

                    # pvwa host
                    # self.assertIn("api_host", config_instance.options_modules[sectionName], msg=f"host not define in options_modules[{sectionName}]")
                    # self.assertEqual(config_instance.options_modules[sectionName]["api_host"], TestConfig_epv.yaml_dict["pvwa"]["host"],
                    #                  msg=f"""Invalid value in options_modules[{sectionName}][api_host]. Expected: {TestConfig_epv.yaml_dict["pvwa"]["host"]!r}""")

                    for attrName in ["host", "keep_cookies", "max_concurrent_tasks", "timeout", "verify"]:
                        self.assertIn(attrName, config_instance.options_modules[sectionName],
                                      msg=f"{attrName} not define in options_modules[{sectionName}]")
                        self.assertEqual(config_instance.options_modules[sectionName][attrName], TestConfig_epv.yaml_dict["pvwa"][attrName],
                                        msg=f"""Invalid value in options_modules[{sectionName}][{attrName}]. Expected: {TestConfig_epv.yaml_dict["pvwa"][attrName]!r}""")


                elif sectionName == "aim":
                    # check information from "connection"
                    self.assertIn("appid", config_instance.options_modules[sectionName],
                                  msg=f"appid not define in options_modules[{sectionName}]")
                    self.assertEqual(config_instance.options_modules[sectionName]["appid"], TestConfig_epv.yaml_dict["connection"]["appid"],
                                    msg=f"""Invalid value in options_modules[{sectionName}][appid]. Expected: {TestConfig_epv.yaml_dict["connection"]["appid"]!r}""" )

                    for attrName in ["keep_cookies", "key", "max_concurrent_tasks", "passphrase", "timeout", "verify"]:
                        self.assertIn(attrName, config_instance.options_modules[sectionName],
                                      msg=f"{attrName} not define in options_modules[{sectionName}]")
                        self.assertEqual(config_instance.options_modules[sectionName][attrName], TestConfig_epv.yaml_dict["AIM"][attrName],
                                        msg=f"""Invalid value in options_modules[{sectionName}][{attrName}]. Expected: {TestConfig_epv.yaml_dict["AIM"][attrName]!r}""")

                elif sectionName == "account":
                    for attrName in ["logon_account_index", "reconcile_account_index"]:
                        self.assertIn(attrName, config_instance.options_modules[sectionName],
                                      msg=f"{attrName} not define in options_modules[{sectionName}]")
                        self.assertEqual(config_instance.options_modules[sectionName][attrName], TestConfig_epv.yaml_dict[sectionName][attrName],
                                        msg=f"""Invalid value in options_modules[{sectionName}][{attrName}]. Expected: {TestConfig_epv.yaml_dict[sectionName][attrName]!r}""")

                elif sectionName == "safe":
                    for attrName in ["cpm", "retention"]:
                        self.assertIn(attrName, config_instance.options_modules[sectionName], msg=f"{attrName} not define in options_modules[{sectionName}]")
                        self.assertEqual(config_instance.options_modules[sectionName][attrName], TestConfig_epv.yaml_dict[sectionName][attrName],
                                        msg=f"""Invalid value in options_modules[{sectionName}][{attrName}]. Expected: {TestConfig_epv.yaml_dict[sectionName][attrName]!r}""")
                else:
                    if config_instance.options_modules[sectionName]:
                        self.fail(msg=f"No validation defined for options_modules[{sectionName}]")


    def test_02_epv_complete_yml(self):
        """ test_02_epv_complete_yml  - Test complete yaml yaml file
            Check all fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        epv_env = self.call_EPV(fnc_name, configFile=TestConfig_epv.yaml_filename, expected_value=TestConfig_epv.epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check=True)

        # Check for global unknown attributes in case new test should be added
        for attrName in vars(epv_env):
            if not attrName.startswith("_"):
                with self.subTest(unknowned=attrName):
                    self.assertIn(attrName, EPV_ATTRIBUTE_NAME,
                                  msg=f"Unknow attribute '{attrName}' in EPV (verify for new validation test): {attrName}")


        # Check for global not defined attributes in case old test should be modified
        vars_def = vars(epv_env)

        for attrName in EPV_ATTRIBUTE_NAME:
            if not attrName.startswith("_"):
                with self.subTest(undefined=attrName):
                    self.assertIn(attrName, vars_def,
                                  msg=f"Undefined attribute '{attrName}' in EPV (verify old validation test): {attrName}")

    def test_03_epv_complete_ser(self):
        """ test_03_epv_complete_ser  - Test complete serialization.
            Check all fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)


        # Adjust validation for serialization
        epv_validation_dict = copy.deepcopy(TestConfig_epv.epv_validation_dict)

        # Remove config.label and config.configfile (keep custom)
        if epv_validation_dict.get("config", None) is not None:
            if epv_validation_dict["config"].get("label", None) is not None:
                del epv_validation_dict["config"]["label"]

            if epv_validation_dict["config"].get("configfile", None) is not None:
                del epv_validation_dict["config"]["configfile"]


        epv_env = self.call_EPV(fnc_name, serialized=TestConfig_epv.serialize_dict, expected_value=epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check = True)

        # Check for unknown attribute in case new test should be added
        for attrName in vars(epv_env):
            if not attrName.startswith("_"):
                self.assertIn(attrName, EPV_ATTRIBUTE_NAME,
                              msg=f"Unknow attribute '{attrName}' in EPV (may add new validation): {attrName}")


    def test_11_upperkey_from_yml(self):
        """ test_11_upperkey_from_yml  - Test uppercase attribute name (yaml file).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        yaml_dict = copy.deepcopy(TestConfig_epv.yaml_dict)

        # PVWA
        yaml_dict["pvwa"]["Max_Concurrent_tAsks"] = yaml_dict["pvwa"].pop("max_concurrent_tasks")
        yaml_dict["PVWA"] = yaml_dict.pop("pvwa")

        # account
        yaml_dict["account"]["LOGON_account_INDEX"] = yaml_dict["account"].pop("logon_account_index")
        yaml_dict["account"]["RECONCILE_account_INDEX"] = yaml_dict["account"].pop("reconcile_account_index")
        yaml_dict["aCCount"] = yaml_dict.pop("account")


        # safe
        yaml_dict["safe"]["CPM"] = yaml_dict["safe"].pop("cpm")
        yaml_dict["safe"]["reTention"] = yaml_dict["safe"].pop("retention")
        yaml_dict["sAfe"] = yaml_dict.pop("safe")

        epv_env = self.call_EPV(fnc_name, yaml_dict=yaml_dict, expected_value=TestConfig_epv.epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check = True)


    def test_12_upperkey_from_ser(self):
        """ test_12_upperkey_from_ser  - Test uppercase attribute name (serialization).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        serialize_dict = copy.deepcopy(TestConfig_epv.serialize_dict)
        epv_validation_dict = copy.deepcopy(TestConfig_epv.epv_validation_dict)

        # EPV
        serialize_dict["Max_Concurrent_tAsks"] = serialize_dict.pop("max_concurrent_tasks")

        # account
        serialize_dict["account"]["LOGON_account_INDEX"] = serialize_dict["account"].pop("logon_account_index")
        serialize_dict["account"]["RECONCILE_account_INDEX"] = serialize_dict["account"].pop("reconcile_account_index")
        serialize_dict["aCCount"] = serialize_dict.pop("account")

        # safe
        serialize_dict["safe"]["CPM"] = serialize_dict["safe"].pop("cpm")
        serialize_dict["safe"]["reTention"] = serialize_dict["safe"].pop("retention")
        serialize_dict["sAfe"] = serialize_dict.pop("safe")

        # Remove config validation (except custom)
        if "config" in epv_validation_dict:
            if "label" in epv_validation_dict["config"]:
                del epv_validation_dict["config"]["label"]
            if "configfile" in epv_validation_dict["config"]:
                del epv_validation_dict["config"]["configfile"]


        epv_env = self.call_EPV(fnc_name, serialized=serialize_dict, expected_value=epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check = True)



    def test_21_default_from_yml(self):
        """ test_21_default_from_yml  - Test default value returned (yaml file).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        yaml_dict = {"AIM": {"host": "host22"}}

        epv_env = self.call_EPV(fnc_name, yaml_dict=yaml_dict,
                                trace_input=True, trace_epv=True, trace_check = False)

        # EPV
        self.assertEqual(epv_env.keep_cookies, aiobastion.config.Config.CYBERARK_DEFAULT_KEEP_COOKIES)
        self.assertEqual(epv_env.max_concurrent_tasks, aiobastion.config.Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS)
        self.assertEqual(epv_env.timeout, aiobastion.config.Config.CYBERARK_DEFAULT_TIMEOUT)
        self.assertEqual(epv_env.verify, aiobastion.config.Config.CYBERARK_DEFAULT_VERIFY)

        # account
        self.assertEqual(epv_env.account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX, epv_env.account.logon_account_index)
        self.assertEqual(epv_env.account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX, epv_env.account.reconcile_account_index)

        # aim
        self.assertEqual(epv_env.AIM.keep_cookies, aiobastion.config.Config.CYBERARK_DEFAULT_KEEP_COOKIES)
        self.assertEqual(epv_env.AIM.max_concurrent_tasks, aiobastion.config.Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS)
        self.assertEqual(epv_env.AIM.timeout, aiobastion.config.Config.CYBERARK_DEFAULT_TIMEOUT)
        self.assertEqual(epv_env.AIM.verify, aiobastion.config.Config.CYBERARK_DEFAULT_VERIFY)

        # safe
        self.assertEqual(epv_env.safe._SAFE_DEFAULT_CPM, epv_env.safe.cpm)
        self.assertEqual(epv_env.safe._SAFE_DEFAULT_RETENTION, epv_env.safe.retention)


    def test_22_default_from_ser(self):
        """ test_22_default_from_ser  - Test default value returned (serialization).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        serialize_dict = {"AIM": {"host": "host22"}}

        epv_env = self.call_EPV(fnc_name, serialized=serialize_dict,
                                trace_input=True, trace_epv=True, trace_check = True)

        # EPV
        self.assertEqual(epv_env.keep_cookies, aiobastion.config.Config.CYBERARK_DEFAULT_KEEP_COOKIES)
        self.assertEqual(epv_env.max_concurrent_tasks, aiobastion.config.Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS)
        self.assertEqual(epv_env.timeout, aiobastion.config.Config.CYBERARK_DEFAULT_TIMEOUT)
        self.assertEqual(epv_env.verify, aiobastion.config.Config.CYBERARK_DEFAULT_VERIFY)

        # account
        self.assertEqual(epv_env.account._ACCOUNT_DEFAULT_LOGON_ACCOUNT_INDEX, epv_env.account.logon_account_index)
        self.assertEqual(epv_env.account._ACCOUNT_DEFAULT_RECONCILE_ACCOUNT_INDEX, epv_env.account.reconcile_account_index)

        # aim
        self.assertEqual(epv_env.AIM.keep_cookies, aiobastion.config.Config.CYBERARK_DEFAULT_KEEP_COOKIES)
        self.assertEqual(epv_env.AIM.max_concurrent_tasks, aiobastion.config.Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS)
        self.assertEqual(epv_env.AIM.timeout, aiobastion.config.Config.CYBERARK_DEFAULT_TIMEOUT)
        self.assertEqual(epv_env.AIM.verify, aiobastion.config.Config.CYBERARK_DEFAULT_VERIFY)

        # safe
        self.assertEqual(epv_env.safe._SAFE_DEFAULT_CPM, epv_env.safe.cpm)
        self.assertEqual(epv_env.safe._SAFE_DEFAULT_RETENTION, epv_env.safe.retention)


    def test_31_synonym_from_yml(self):
        """ test_31_synonym_from_yml  - Test synonym (yaml file).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        yaml_dict = copy.deepcopy(TestConfig_epv.yaml_dict)
        #epv_validation_dict = copy.deepcopy(TestConfig_epv.epv_validation_dict)

        # PVWA
        yaml_dict["pvwa"]["ca"] = yaml_dict["pvwa"].pop("verify")
        yaml_dict["pvwa"]["maxtasks"] = yaml_dict["pvwa"].pop("max_concurrent_tasks")

        if len(yaml_dict["pvwa"]) == 0:
            del yaml_dict["pvwa"]

        # AIM vs Connection
        yaml_dict["AIM"]["appid"] = yaml_dict["connection"].pop("appid")

        if len(yaml_dict["AIM"]) == 0:
            del yaml_dict["AIM"]

        # account vs Custom
        yaml_dict["custom"]["LOGON_ACCOUNT_INDEX"] = yaml_dict["account"].pop("logon_account_index")
        yaml_dict["custom"]["RECONCILE_ACCOUNT_INDEX"] = yaml_dict["account"].pop("reconcile_account_index")

        if len(yaml_dict["account"]) == 0:
            del yaml_dict["account"]

        # safe vs global section
        yaml_dict["cpm"] = yaml_dict["safe"].pop("cpm")
        yaml_dict["retention"] = yaml_dict["safe"].pop("retention")

        if len(yaml_dict["safe"]) == 0:
            del yaml_dict["safe"]

        epv_env = self.call_EPV(fnc_name, yaml_dict=yaml_dict, expected_value=TestConfig_epv.epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check = True)


    def test_32_synonym_from_ser(self):
        """ test_32_synonym_from_ser - Test synonym (serialization).
            Check some fields in EPV instance class returned.
        """

        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        serialize_dict = copy.deepcopy(TestConfig_epv.serialize_dict)
        epv_validation_dict = copy.deepcopy(TestConfig_epv.epv_validation_dict)

        # account vs Custom
        serialize_dict["custom"]["LOGON_ACCOUNT_INDEX"] = serialize_dict["account"].pop("logon_account_index")
        serialize_dict["custom"]["RECONCILE_ACCOUNT_INDEX"] = serialize_dict["account"].pop("reconcile_account_index")

        if len(serialize_dict["account"]) == 0:
            del serialize_dict["account"]

        # safe vs global section
        serialize_dict["cpm"] = serialize_dict["safe"].pop("cpm")
        serialize_dict["retention"] = serialize_dict["safe"].pop("retention")

        if len(serialize_dict["safe"]) == 0:
            del serialize_dict["safe"]

        if "config" in epv_validation_dict:
            del epv_validation_dict["config"]

        epv_env = self.call_EPV(fnc_name, serialized=serialize_dict, expected_value=epv_validation_dict,
                                trace_input=True, trace_epv=True, trace_check = True)


    def test_41_raise_unknown_yml(self):
        """ test_41_raise_unknown_yml - Test error for unkown attribute (yaml file).
            Check section fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        yaml_dict = copy.deepcopy(TestConfig_epv.yaml_dict)

        # -------------------------------------
        # 1) Wrong global field
        # -------------------------------------
        yaml_dict["a_wrong_field"] = "This-is-wrong"

        with self.subTest(section="global"):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                        r"^Unknown attribute 'a_wrong_field' in"):
                self.call_EPV(f"{fnc_name} - wrong field in section global", yaml_dict=yaml_dict,
                            raise_condition=True)

        del yaml_dict["a_wrong_field"]


        # -------------------------------------
        # 2) Wrong EPV section (modules)
        # -------------------------------------
        for section_name in aiobastion.config.Config.CYBERARK_OPTIONS_MODULES_LIST:
            if section_name == "cyberark":
                continue

            if section_name == "aim":
                section_name = "AIM"

            delete_section = False

            if section_name not in yaml_dict:
                delete_section = True
                yaml_dict[section_name] = {}

            yaml_dict[section_name]["a_wrong_field"] = "This-is-wrong"

            with self.subTest(section=section_name):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Unknown attribute '{section_name.lower()}/a_wrong_field' in "):
                    self.call_EPV(f"{fnc_name} - wrong field in section_name {section_name}", yaml_dict=yaml_dict,
                                  raise_condition=True)

            if delete_section:
                del yaml_dict[section_name]
            else:
                del yaml_dict[section_name]["a_wrong_field"]

        # ---------------------------------------------
        # 3) Wrong EPV field (connection/user_search)
        # ---------------------------------------------
        yaml_dict["connection"]["user_search"]["a_wrong_field"] = "This-is-wrong"

        with self.subTest(section="user_search"):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, r"^invalid parameter in "):
                self.call_EPV(f"{fnc_name} - wrong field in connection/user_search", yaml_dict=yaml_dict,
                                trace_input=True, raise_condition=True)

        del yaml_dict["connection"]["user_search"]["a_wrong_field"]


    def test_42_raise_unknown_ser(self):
        """ test_42_raise_unknown_ser  - Test error for unknown attribute (serialization).
            Check section fields in EPV instance class returned.
        """

        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        serialize_dict = copy.deepcopy(TestConfig_epv.serialize_dict)

        # -------------------------------------
        # 1) Wrong global field
        # -------------------------------------
        serialize_dict["a_wrong_field"] = "This-is-wrong"

        with self.subTest(section="Global"):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                        r"^Unknown attribute 'a_wrong_field' in"):
                # epv_env = aiobastion.EPV(serialized=serialize_dict)
                self.call_EPV(f"{fnc_name} - wrong field in section global", serialized=serialize_dict,
                            raise_condition=True)

        del serialize_dict["a_wrong_field"]

        # -------------------------------------
        # 2) Wrong EPV field (all modules)
        # -------------------------------------
        for section_name in aiobastion.config.Config.CYBERARK_OPTIONS_MODULES_LIST:
            if section_name == "cyberark":
                continue

            if section_name == "aim":
                section_name = "AIM"

            delete_section = False

            if section_name not in serialize_dict:
                delete_section = True
                serialize_dict[section_name] = {}

            serialize_dict[section_name]["a_wrong_field"] = "This-is-wrong"

            with self.subTest(section=section_name):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Unknown attribute '{section_name.lower()}/a_wrong_field' in "):
                    self.call_EPV(f"{fnc_name} - wrong field in section {section_name}", serialized=serialize_dict,
                                raise_condition=True)

            if delete_section:
                del serialize_dict[section_name]
            else:
                del serialize_dict[section_name]["a_wrong_field"]

        # ---------------------------------------------
        # 3) Wrong EPV field user_search
        # ---------------------------------------------
        serialize_dict["user_search"]["a_wrong_field"] = "This-is-wrong"

        with self.subTest(section="user_search"):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, "^invalid parameter in 'user_search': "):
                self.call_EPV(f"{fnc_name} - wrong field in user_search", serialized=serialize_dict,
                                raise_condition=True)

        del serialize_dict["user_search"]["a_wrong_field"]


    def test_51_raise_duplicate_yml(self):
        """ test_51_raise_duplicate_yml  - Test error for duplicate (yaml file).
            Check some fields in EPV instance class returned.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        yaml_dict = copy.deepcopy(TestConfig_epv.yaml_dict)

        # ---------------------------------------------
        # 1) accout vs custom
        # ---------------------------------------------
        for attrName in ["LOGON_ACCOUNT_INDEX", "reconcile_account_index"]:
            yaml_dict["custom"][attrName] = yaml_dict["account"][attrName.lower()]

            with self.subTest(attrName=attrName):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                        f"^Duplicate definition: move 'logon_account_index' and 'reconcile_account_index' from 'custom' to 'account' section in"):
                    self.call_EPV(f"{fnc_name} - duplicate field account/{attrName}", yaml_dict=yaml_dict,
                                raise_condition=True)

            del yaml_dict["custom"][attrName]

        # ---------------------------------------------
        # 2) safe vs global section
        # ---------------------------------------------
        for attrName in ["cpm", "RETENTION"]:
            yaml_dict[attrName] = yaml_dict["safe"][attrName.lower()]

            with self.subTest(attrName=attrName):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                        f"^Duplicate definition: Move 'cpm' and 'retention' to the 'safe' definition"):
                    self.call_EPV(f"{fnc_name} - duplicate field safe/{attrName}", yaml_dict=yaml_dict,
                                raise_condition=True)

            del yaml_dict[attrName]

        # ---------------------------------------------
        # 3) connection vs AIM (appid)
        # ---------------------------------------------
        attrName = "appid"
        add_section = None

        if "connection" in yaml_dict and attrName in yaml_dict["connection"]:
            add_section = "AIM"
        elif "AIM" in yaml_dict and attrName in yaml_dict["AIM"]:
            add_section = "connection"

        yaml_dict[add_section][attrName] = "appid_test"

        with self.subTest(add_section=add_section, attrName=attrName):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                        f"^Duplicate key 'aim/appid' in "):
                    self.call_EPV(f"{fnc_name} - duplicate field aim/{attrName}", yaml_dict=yaml_dict,
                                raise_condition=True)

        del yaml_dict[add_section]["appid"]

        # ---------------------------------------------
        # 4) same key lowercase vs uppercase
        # ---------------------------------------------
        attrName = "host"
        yaml_dict["pvwa"]["HOST"] = yaml_dict["pvwa"][attrName]

        with self.subTest(attrName=attrName):
            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                        f"^Duplicate key '/pvwa/host' in "):
                    self.call_EPV(f"{fnc_name} - duplicate field pvwa/host (lower/uppercase)", yaml_dict=yaml_dict,
                            raise_condition=True)

        del yaml_dict["pvwa"]["HOST"]


    def test_52_raise_duplicate_ser(self):
        """ test_52_raise_duplicate_ser - Test error for duplicate (serialization).
            Check some fields in EPV instance class returned.
        """

        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        serialize_dict = copy.deepcopy(TestConfig_epv.serialize_dict)

        # ---------------------------------------------
        # 1) accout vs custom
        # ---------------------------------------------
        for attrName in ["LOGON_ACCOUNT_INDEX", "reconcile_account_index"]:
            serialize_dict["custom"][attrName] = serialize_dict["account"][attrName.lower()]

            with self.subTest(attrName=attrName):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                        f"^Duplicate definition: move 'logon_account_index' and 'reconcile_account_index' from 'custom' to 'account' section in"):
                    # epv_env = aiobastion.EPV(serialized=serialize_dict)
                    self.call_EPV(f"{fnc_name} - duplicate field account/{attrName}", serialized=serialize_dict,
                                raise_condition=True)

            del serialize_dict["custom"][attrName]

        # ---------------------------------------------
        # 2) safe vs global section
        # ---------------------------------------------
        for attrName in ["cpm", "RETENTION"]:
            serialize_dict[attrName] = serialize_dict["safe"][attrName.lower()]

            with self.subTest(attrName=attrName):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                        f"^Duplicate definition: Move 'cpm' and 'retention' to the 'safe' definition"):
                    # epv_env = aiobastion.EPV(serialized=serialize_dict)
                    self.call_EPV(f"{fnc_name} - duplicate field safe/{attrName}", serialized=serialize_dict,
                                    raise_condition=True)

            del serialize_dict[attrName]

        # ---------------------------------------------
        # 2) same key lowercase vs uppercase
        # ---------------------------------------------
        serialize_dict["API_HOST"] = serialize_dict["api_host"]

        with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, f"^Duplicate key '/"):
            self.call_EPV(f"{fnc_name} - duplicate field api_host  (lower/uppercase)", serialized=serialize_dict,
                          raise_condition=True)

        del serialize_dict["API_HOST"]


    def test_61_raise_typecheck_yml(self):
        """ test_13_raise_typecheck_yml - Test error for type definition (yaml file)

        type: integer
            pvwa                timeout
            pvwa(1)             max_concurrent_tasks
            pvwa(1)             maxtasks
            retention
            aim                 timeout
            aim                 max_concurrent_tasks
            custom(3)           LOGON_ACCOUNT_INDEX
            custom(3)           RECONCILE_ACCOUNT_INDEX
            account(3)          logon_account_index
            account(3)          reconcile_account_index
            safe                retention

        Type: boolean
            pvwa                keep_cookies

        type: string or boolean
            aim                 verify
            pvwa                ca
            pvwa                verify

        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        # -------------------------------------
        # 2) Wrong EPV field (pvwa)
        # -------------------------------------
        check_int = [
            ("pvwa", "timeout"),
            ("pvwa", "max_concurrent_tasks"),
            ("pvwa", "maxtasks"),
            ("",     "retention"),
            ("AIM", "timeout"),
            ("AIM", "max_concurrent_tasks"),
            ("custom", "LOGON_ACCOUNT_INDEX"),
            ("custom", "RECONCILE_ACCOUNT_INDEX"),
            ("account", "logon_account_index"),
            ("account", "reconcile_account_index"),
            ("safe", "retention"),
        ]

        check_bool = [
            ("pvwa", "keep_cookies"),
        ]

        check_bool_str = [
            ("AIM", "verify"),
            ("pvwa", "ca"),
            ("pvwa", "verify"),
        ]

        # Test integer
        for section_name, attrName in check_int:
            if section_name:
                yaml_dict = {section_name: {attrName: "err"}}
            else:
                yaml_dict = {attrName: "err"}

            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, f"^Invalid integer value "):
                self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", yaml_dict=yaml_dict,
                              raise_condition=True)

        # Test boolean
        for section_name, attrName in check_bool:
            if section_name:
                yaml_dict = {section_name: {attrName: "err"}}
            else:
                yaml_dict = {attrName: "err"}

            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, f"^Invalid boolean value "):
                self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", yaml_dict=yaml_dict,
                              raise_condition=True)

        # Test verify (string or boolean)
        for section_name, attrName in check_bool_str:
            if section_name:
                yaml_dict = {section_name: {attrName: 1}}
            else:
                yaml_dict = {attrName: 1}

            with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, f"^Parameter type invalid "):
                self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", yaml_dict=yaml_dict,
                              raise_condition=True)


    def test_62_raise_typecheck_ser(self):
        """ test_14_raise_typecheck_ser - Test error for type definition (serialization)

        type: integer
            timeout
            max_concurrent_tasks
            retention
            aim                 timeout
            aim                 max_concurrent_tasks
            custom(3)           LOGON_ACCOUNT_INDEX
            custom(3)           RECONCILE_ACCOUNT_INDEX
            account(3)          logon_account_index
            account(3)          reconcile_account_index
            safe                retention

        Type: boolean
            keep_cookies

        type: string or boolean
            aim                 verify
            verify

        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        # -------------------------------------
        # 2) Wrong EPV field (pvwa)
        # -------------------------------------
        check_int = [
            ("",        "timeout"),
            ("",        "max_concurrent_tasks"),
            ("",        "retention"),
            ("AIM",     "timeout"),
            ("AIM",     "max_concurrent_tasks"),
            ("custom",  "LOGON_ACCOUNT_INDEX"),
            ("custom",  "RECONCILE_ACCOUNT_INDEX"),
            ("account", "logon_account_index"),
            ("account", "reconcile_account_index"),
            ("safe",    "retention"),
        ]

        check_bool = [
            ("", "keep_cookies"),
        ]

        check_bool_str = [
            ("AIM", "verify"),
            ("", "verify"),
        ]

        # Test integer
        for section_name, attrName in check_int:
            if section_name:
                serialize_dict = {section_name: {attrName: "err"}}
            else:
                serialize_dict = {attrName: "err"}

            with self.subTest(attrName=attrName, type="integer"):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Invalid integer value "):
                    self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", serialized=serialize_dict,
                                raise_condition=True)

        # Test boolean
        for section_name, attrName in check_bool:
            if section_name:
                serialize_dict = {section_name: {attrName: "err"}}
            else:
                serialize_dict = {attrName: "err"}

            with self.subTest(attrName=attrName, type="bool"):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Invalid boolean value "):
                    self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", serialized=serialize_dict,
                              raise_condition=True)

        # Test verify (string or boolean)
        for section_name, attrName in check_bool_str:
            if section_name:
                serialize_dict = {section_name: {attrName: 1}}
            else:
                serialize_dict = {attrName: 1}

            with self.subTest(attrName=attrName, type="string/bool"):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Parameter type invalid "):
                    self.call_EPV(f"{fnc_name} - Invalid type {section_name}/{attrName}", serialized=serialize_dict,
                                raise_condition=True)


    def test_71_raise_account_validation(self):
        """ test_71_raise_account_validation - Test error for wrong value in Account definition (yaml file and serialization)
        """
        fnc_name = inspect.currentframe().f_code.co_name

        for attrName in ["logon_account_index", "reconcile_account_index"]:
            serialize_dict = {"account": {attrName: 10}}

            with self.subTest(attrName=attrName,type="ser"):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Invalid value for attribute 'account/{attrName}' "):
                    self.call_EPV(f"{fnc_name} - account/reconcile_account_index (ser)", serialized=serialize_dict,
                                    raise_condition=True)

            with self.subTest(attrName=attrName,type="Yaml"):
                with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException,
                                            f"^Invalid value for attribute 'account/{attrName}' "):
                    self.call_EPV(f"{fnc_name} - account /reconcile_account_index (Yaml)", yaml_dict=serialize_dict,
                                    raise_condition=True)


    def test_81_raise_no_parm(self):
        """ test_81_raise_no_parm - Test error for missing parameter in EPV call
        """

        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        with self.assertRaisesRegex(aiobastion.exceptions.AiobastionConfigurationException, "Internal error: no configfile and no serialized"):
                    # epv_env = aiobastion.EPV(serialized=serialize_dict)
                    self.call_EPV(f"{fnc_name} - No param")



    def test_91_to_json(self):
        """ test_91_to_json - Test <EPV>.to_json function call
            Check all expected value fro <EPV>.to_json.
        """
        fnc_name = inspect.currentframe().f_code.co_name
        self.writelog(HEADER, fnc_name)

        # Remove hidden field
        validate_to_json = copy.deepcopy(TestConfig_epv.serialize_dict)

        # Remove hidden field for validation
        del validate_to_json["password"]
        del validate_to_json["username"]
        del validate_to_json["user_search"]
        del validate_to_json["custom"]
        del validate_to_json["AIM"]["passphrase"]

        epv_env = self.call_EPV(fnc_name, serialized=TestConfig_epv.serialize_dict, expected_value=None,
                                trace_input=True, trace_epv=True, trace_check = False)

        json_dict =  epv_env.to_json()

        self.write_pprint(f" {fnc_name} - to_json return ",json_dict)

        self.writelog(f" {fnc_name} - check value ".center(100, "-"))


        # Check all expected value
        self.check_section_value(f"{fnc_name}", json_dict, validate_to_json, trace_check=True)

        self.writelog(f" {fnc_name} - check value (end) ".center(100, "-"))


if __name__ == '__main__':
    if sys.platform == 'win32':
        # Turned out, using WindowsSelectorEventLoop has functionality issues such as:
        #     Can't support more than 512 sockets
        #     Can't use pipe
        #     Can't use subprocesses
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    unittest.main()
