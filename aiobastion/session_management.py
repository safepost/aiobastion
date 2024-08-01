# -*- coding: utf-8 -*-

from .exceptions import CyberarkException, CyberarkAPIException, AiobastionConfigurationException


class SessionManagement:
    # _SESSIONMANAGEMENT_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        self.epv = epv

        _section = "sessionmanagement"
        _config_source = self.epv.config.config_source

        for _k in kwargs.keys():
            raise AiobastionConfigurationException(f"Unknown attribute '{_section}/{_k}' in {_config_source}")

    async def get_all_connection_components(self):
        """
        :return: A list of all connection components
        """
        return await self.epv.handle_request("get", f"API/PSM/Connectors/")

    @classmethod
    def _init_validate_class_attributes(cls, serialized: dict, section: str, configfile: str = None) -> dict:
        """_init_validate_class_attributes      Initialize and validate the SessionManagement definition (file configuration and serialized)

        Arguments:
            serialized {dict}           Definition from configuration file or serialization
            section {str}               Verified section name

        Keyword Arguments:
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Returns:
            new_serialized {dict}       SessionManagement defintion
        """
        if not configfile:
            configfile = "serialized"

        new_serialized = {}

        for k in serialized.keys():
            keyname = k.lower()

            # # Special validation: integer, boolean
            # if keyname in ["xxx"]:
            #     new_serialized[keyname] = validate_integer(configfile, f"{section}/{keyname}", serialized[k])

            if keyname in SessionManagement._SERIALIZED_FIELDS:
                # String definition
                if serialized[k] is not None:
                    new_serialized[keyname] = serialized[k]
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{section}/{k}' in {configfile}")

        # Default values if not set
        # new_serialized.setdefault("xxx", SessionManagement._SESSIONMANAGEMENT_DEFAULT_XXX)

        return new_serialized

    def to_json(self):
        serialized = {}

        for attr_name in SessionManagement._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized
