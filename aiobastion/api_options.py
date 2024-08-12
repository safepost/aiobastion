# -*- coding: utf-8 -*-

import warnings
from .exceptions import AiobastionConfigurationException
from typing import Optional


class Api_options:
    """ Api_options - global API options """
    _SERIALIZED_FIELDS = ["deprecated_warning"]
    API_OPTIONS_DEFAULT_DEPRECATED_WARNING = True

    deprecated_warning_enabled_ind = None       # is deprecated_warning already setup?

    def __init__(self, epv, *, deprecated_warning: Optional[bool] = None, **kwargs):
        # TODO: add option to disable err.http_status  403 and 409 (for safe.py)
        # TODO: add logger full setup (see logging.config)
        # TODO: Add full trace Debugging by level and modules
        #           level Ex.: 1 = errors only, 2 = High level funtion trace,
        #                      3 = CyberArk call & returned values, 4 = CyberArk Communication (ssl, cockies, ...), 5 = Full trace)

        self.epv = epv

        _section = "api_options"
        _config_source = self.epv.config.config_source

        self.deprecated_warning = Api_options.set_deprecated_warning(deprecated_warning, _config_source, f"{_section}/deprecated_warning")

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}")


    def to_json(self):
        serialized = {}

        for attr_name in Api_options._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

    @classmethod
    def set_deprecated_warning(cls, value: Optional[bool] = None,  _config_source: Optional[str] = None, _section: Optional[str]=None) -> bool:
        """ Set/reset deprecated_warning option

        :param bool value: Activate (True) or deactivate (False) aiobastion deprecated warning option
        :raise AiobastionConfigurationException(f"Invalid value 'value' in 'set_deprecated_warning' funtion (expected bool): ...")
        """
        if _config_source is None and _section is None:
            _config_source = "'set_deprecated_warning' function"
            _section = "value"
        elif _config_source is None:
            _config_source = "'set_deprecated_warning' function"
        elif _section is None:
            _section = "api_options/deprecated_warning"

        value = Api_options.validate_bool(_config_source, _section, value, Api_options.API_OPTIONS_DEFAULT_DEPRECATED_WARNING)

        if cls.deprecated_warning_enabled_ind is not None and value == cls.deprecated_warning_enabled_ind:
            return  cls.deprecated_warning_enabled_ind   # It is already setup

        if value:
            cls.deprecated_warning_enabled_ind = True
            warnings.filterwarnings("module", category=DeprecationWarning, module='^aiobastion\.')
        else:
            cls.deprecated_warning_enabled_ind = False
            warnings.filterwarnings("ignore", category=DeprecationWarning, module='^aiobastion\.')

        return cls.deprecated_warning_enabled_ind


    # This is a copy of config.validate_bool.
    # It is here to avoid circular imports.
    @staticmethod
    def validate_bool(config_source: str, section_name: str, val,  default_value = None) -> bool:
        if default_value and (val is None or (isinstance(val, str) and len(val.strip()) == 0)):
            return default_value

        if isinstance(val, bool):
            rt = val
        else:
            raise AiobastionConfigurationException(f"Invalid value '{section_name}' "
                                                f"in {config_source} (expected bool): {val!r}")

        return rt
