# -*- coding: utf-8 -*-

class CyberarkException(Exception):
    """
    This Exception is raised on unhandled Cyberark error
    """
    pass


class CyberarkNotFoundException(CyberarkException):
    """
    This exception is raised on 404
    """
    pass

class GetTokenException(Exception):
    """
    This exception is raised when the token can't be obtained
    """
    pass


class CyberarkAPIException(Exception):
    """
    This exception is raised when CyberArk API result is not 200, 201 or 204
    It provides - when possible - err_message and details
    """
    def __init__(self, http_status, err_code, err_message, details=" "):
        self.http_status = http_status
        self.err_code = err_code
        self.err_message = err_message
        self.details = details

    def __str__(self):
        error = f"HTTP {self.http_status}, {self.err_code} : {self.err_message}"
        if self.details != "":
            error += f" || Additional Details : {self.details}"
        return error
    pass


class AiobastionConfigurationException(Exception):
    """
    This exception is raised when a required field in configuration was not provided
    """
    pass

class AiobastionException(Exception):
    """
    This exception is raised when a function does not have correct parameters
    and thus can't call the API.
    """
    pass


class ChallengeResponseException(Exception):
    """
    This exception is raised on login when the user need to authenticate again with passcode
    """
    pass

class CyberarkAIMnotFound(Exception):
    """
    This exception is raised when AIM has not found the specified account (HTTP 404)
    """
    def __init__(self, http_status, err_code, err_message, details=" "):
        self.http_status = http_status
        self.err_code = err_code
        self.err_message = err_message
        self.details = details

    def __str__(self):
        error = f"Account not found. HTTP {self.http_status}, {self.err_code} : {self.err_message}"
        if self.details != "":
            error += f" || Additional Details : {self.details}"
        return error
    pass
