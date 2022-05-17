# -*- coding: utf-8 -*-
import asyncio
import base64

import aiohttp
from .abstract import Vault
from .exceptions import CyberarkException, CyberarkAPIException


class Platform:
    def __init__(self, epv: Vault):
        self.epv = epv
        # self.session = self.epv.session

    async def get_target_platforms(self, active: bool = None, systemType: str = None, periodicVerify: bool = None,
                                   manualVerify: bool = None, periodicChange: bool = None, manualChange: bool = None,
                                   automaticReconcile: bool = None, manualReconcile: bool = None):
        """
        Get target platforms that meet given criteria (or all platforms)

        :param active: Boolean
        :param systemType: str
        :param periodicVerify: Boolean
        :param manualVerify: Boolean
        :param periodicChange: Boolean
        :param manualChange: Boolean
        :param automaticReconcile: Boolean
        :param manualReconcile: Boolean
        :return: List of target platform dictionaries
        """

        search = []
        filtered_args = {k: v for k, v in locals().items() if v and k not in ["self"]}
        for param, value in filtered_args.items():
            if value is not None:
                search.append(f"{param} eq {value}")

        if len(search) == 0:
            params = None
        else:
            # Cyberark doc says "Filters" but it's not working on 12.2, "filter" works
            filters = " AND ".join(search)
            params = {"filter": filters}
        return await self.epv.handle_request("get", 'API/Platforms/Targets', params=params,
                                             filter_func=lambda result: result["Platforms"])

    async def get_platforms_details(self, platform_name: str):
        """
        Get details for a given platform name

        :param platform_name: Platform name
        :return: a dictionary with the details of the platform
        """
        return await self.epv.handle_request("get", f"API/Platforms/{platform_name}")

    async def search_target_platform(self, search: str = ""):
        """
        Free search on target platforms.
        Beware that for a search it can return several platforms
        If you want to search on a particular platform better use get_target_platform_details

        :param search: free search
        :return: a list of found platforms
        """
        if search != "":
            params = {"search": search}
        else:
            params = {}
        return await self.epv.handle_request("get", 'API/Platforms/Targets', params=params,
                                             filter_func=lambda result: result["Platforms"])

    async def get_target_platform_details(self, platform_name: str):
        """
        Give detail about one particular platform

        :param platform_name: Name of the platform
        :return: a dict with details of the platform
        """
        for pf in await self.search_target_platform(platform_name):
            if pf["Name"] == platform_name:
                return pf

    async def get_target_platform_unique_id(self, platformID: str):
        """
        Retrieve the base64 ID of a platform

        :param platformID: the ID of platform (eg : WinDesktopLocal) or the name (eg "Oracle Database")
        :return: base64 ID of the platform
        """
        # the only way to find the base64 ID of a platform is to find the platform with get_target_platform
        # but this method don't allow us to find a platform with its platformID (weird)
        # so we extract all platforms, find the right one, and then return the ID
        # we made the assertion that platformID is unique
        # if the user is gentle enough to provide us the name, we still accept it

        # get all platforms
        all_platforms = await self.epv.handle_request("get", 'API/Platforms/Targets',
                                                      filter_func=lambda result: result["Platforms"])
        # find the good platform and return the ID
        for platform in all_platforms:
            if platform["PlatformID"] == platformID or platform["Name"] == platformID:
                return platform["ID"]

    async def del_target_plaform(self, pfid):
        """
        Delete target platform using ID
        You can get ID using get_target_platform_details

        :param pfid: Platform ID of the platform
        :return: Boolean
        """
        return await self.epv.handle_request("delete", f"API/Platforms/Targets/{str(pfid)}")

    async def export_platform(self, pfid: str, outdir: str):
        """
        Export platform files to outdir (existing directory)
        
        :param pfid: 
        :param outdir: 
        :return: 
        """
        url, head = self.epv.get_url(f"API/Platforms/{str(pfid)}/Export")

        try:
            async with aiohttp.ClientSession(headers=head) as session:
                async with session.request("post", url, **self.epv.request_params) as req:
                    if req.status != 200:
                        content = await req.json()
                        try:
                            raise CyberarkAPIException(req.status, content["ErrorCode"], content["ErrorMessage"])
                        except Exception:
                            raise CyberarkException(content)

                    file_content = await req.read()
                    with open(outdir + "/" + pfid + ".zip", "wb") as pf_file:
                        pf_file.write(file_content)

        except Exception as err:
            return f"{pfid} is not exportable : {str(err)}"
        return True

    async def get_target_platform_connection_components(self, platformId):
        """
        Get the list of PSMConnectors for a platform unique ID

        :param platformId: the base64 ID of platform (use get_target_platform_unique_id)
        :return a list of connection component
        """
        return await self.epv.handle_request(
            "get",
            f"API/Platforms/Targets/{platformId}/PrivilegedSessionManagement",
            filter_func=lambda x: x["PSMConnectors"])

    async def get_session_management_policy(self, platformId):
        """
        Get management policy info for a platform

        :param platformId: The base64 UD of platform (use get_target_platform_unique_id)
        :return: a dict with management policy infos
        """
        return await self.epv.handle_request(
            "get",
            f"API/Platforms/Targets/{platformId}/PrivilegedSessionManagement"
        )

    async def export_all_platforms(self, outdir: str):
        pf_id = [pf["PlatformID"] for pf in await self.get_target_platforms()]
        coros = []
        for pfid in pf_id:
            coros.append(self.export_platform(pfid, outdir))
        await asyncio.gather(*coros)

        return True

    async def import_connection_component(self, zipfile: str):
        """
        Import connection component

        :param zipfile: Contains the connection component info (or generated with cyberark tool)
        :return: True
        """
        with open(zipfile, 'rb') as f:
            fc = f.read()
            fb64 = base64.b64encode(fc).decode("utf-8")
        data = {"ImportFile": fb64}
        return await self.epv.handle_request(
            "post",
            f"API/ConnectionComponents/Import", data=data
        )
