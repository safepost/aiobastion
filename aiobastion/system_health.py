from .exceptions import AiobastionConfigurationException

class SystemHealth:
    # _SYSTEMHEALTH_DEFAULT_XXX = <value>

    # List of attributes from configuration file and serialization
    _SERIALIZED_FIELDS = []

    def __init__(self, epv):
        self.epv = epv

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

    @classmethod
    def _init_validate_class_attributes(cls, serialized: dict, section: str, configfile: str = None) -> dict:
        """_init_validate_class_attributes      Initialize and validate the SystemHealth definition (file configuration and serialized)

        Arguments:
            serialized {dict}           SystemHealth defintion
            section {str}               Verified section name

        Keyword Arguments:
            configfile {str}            Name of the configuration file

        Raises:
            AiobastionConfigurationException

        Returns:
            new_serialized {dict}       SystemHealth defintion
        """
        if not configfile:
            configfile = "serialized"

        new_serialized = {}

        for k in serialized.keys():
            keyname = k.lower()

            # # Special validation: integer, boolean
            # if keyname in ["xxx"]:
            #     new_serialized[keyname] = validate_integer(configfile, f"{section}/{keyname}", serialized[k])

            if keyname in SystemHealth._SERIALIZED_FIELDS:
                # String definition
                if serialized[k] is not None:
                    new_serialized[keyname] = serialized[k]
            else:
                raise AiobastionConfigurationException(f"Unknown attribute '{section}/{k}' in {configfile}")

        # Default values if not set
        #     new_serialized.setdefault("xxx", SystemHealth._SYSTEMHEALTH_DEFAULT_XXX)

        return new_serialized

    def to_json(self):
        serialized = {}

        for attr_name in SystemHealth._SERIALIZED_FIELDS:
            v = getattr(self, attr_name, None)

            if v is not None:
                serialized[attr_name] = v

        return serialized

