from aiobastion.abstract import Vault
from .exceptions import (
    CyberarkAPIException, CyberarkException, AiobastionException
)


class SystemHealth:
    def __init__(self, epv: Vault):
        self.epv = epv

    async def summary(self):
        url = f"API/ComponentsMonitoringSummary/"

        return await self.epv.handle_request("get", url, filter_func=lambda x: x["Components"])

    async def details(self, component_id):
        """

        @param component_id: PVWA, SessionManagement, CPM, PTA or AIM
        @return:
        """
        url = f"API//ComponentsMonitoringDetails/{component_id}/"

        return await self.epv.handle_request("get", url, filter_func=lambda x: x["ComponentsDetails"])
