from .exceptions import AiobastionConfigurationException

class SystemHealth:
    # _SYSTEMHEALTH_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv, **kwargs):
        self.epv = epv

        _section = "systemhealth"
        _config_source = self.epv.config.config_source

        # Check for unknown attributes
        if kwargs:
            raise AiobastionConfigurationException(f"Unknown attribute in section '{_section}' from {_config_source}: {', '.join(kwargs.keys())}")

    async def summary(self):
        url = f"API/ComponentsMonitoringSummary/"

        return await self.epv.handle_request("get", url, filter_func=lambda x: x["Components"])

    async def details(self, component_id):
        """

        :param component_id: PVWA, SessionManagement, CPM, PTA or AIM
        :return:
        """
        url = f"API//ComponentsMonitoringDetails/{component_id}/"

        return await self.epv.handle_request("get", url, filter_func=lambda x: x["ComponentsDetails"])


    def to_json(self):
        serialized = {}

        for attr_name in SystemHealth._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

