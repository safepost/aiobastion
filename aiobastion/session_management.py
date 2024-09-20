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

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}")

    async def get_all_connection_components(self):
        """
        :return: A list of all connection components
        """
        return await self.epv.handle_request("get", f"API/PSM/Connectors/")


    def to_json(self):
        serialized = {}

        for attr_name in SessionManagement._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized
