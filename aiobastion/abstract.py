# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from .config import Config
from typing import List


class PrivilegedAccount(ABC):
    @abstractmethod
    def __init__(self):
        self.platformAccountProperties = None
        self.address: str = ""
        self.secret = ""
        self.remoteMachinesAccess = None
        self.secretManagement = None
        self.secretType = "password"
        self.platformAccountProperties = {}
        self.safeName = ""
        self.platformId = ""
        self.userName = ""
        self.address = ""
        self.name = ""
        self.id = ""

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def to_json(self) -> dict:
        pass

    @abstractmethod
    def cpm_status(self) -> bool:
        pass


class Account(ABC):
    @abstractmethod
    def search_account_by(self, keywords=None, username=None, address=None, safe=None,
                          platform=None, name=None, ip=None) -> List[PrivilegedAccount]:
        pass


class Vault(ABC):
    config: Config
    request_params: dict
    cpm: str
    retention: int

    @abstractmethod
    def __init__(self):
        self.accountgroup = None
        self.account = None
        self.safe = None

    @abstractmethod
    def logoff(self):
        pass

    @abstractmethod
    def login(self):
        pass

    @abstractmethod
    def get_url(self, url):
        """
        Part of URL after PasswordVault/
        :param url: Part of URL after PasswordVault/
        :return: url and head of the requests
        """
        pass

    @abstractmethod
    def get_version(self):
        """
        Return PVWA version
        Example : 11.7.2
        """
        pass

    @abstractmethod
    def handle_request(self, method: str, short_url: str, data=None, params=None, filter_func=None):
        """
        :param method: post, get, put
        :param short_url: part of URL after PasswordVault/
        :param data: dict representing the body (when needed)
        :param params: dict representing params of the URL (param1=foo1&param2=foo2..)
        :param filter_func: for example : lambda result: result["id"] if API json result has "id" key
        """
        pass

    def versiontuple(self, param):
        """
        Allow comparison between EPV version
        eg : if self.epv.versiontuple(self.epv.get_version()) > self.epv.versiontuple("12.1.1"):
        @param param: string with version, eg 12.1.1
        @return: tuple
        """
        pass
