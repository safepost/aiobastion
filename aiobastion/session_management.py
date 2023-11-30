# -*- coding: utf-8 -*-

from .exceptions import CyberarkException, CyberarkAPIException


class SessionManagement:
    def __init__(self, epv):
        self.epv = epv

    async def get_all_connection_components(self):
        """
        :return: A list of all connection components
        """
        return await self.epv.handle_request("get", f"API/PSM/Connectors/")
