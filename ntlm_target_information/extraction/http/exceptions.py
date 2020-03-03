from aiohttp import ClientResponse

from ntlm_target_information.exceptions import ExtractionError


class HTTPNTLMExtractionError(ExtractionError):
    def __init__(self, msg: str, response: ClientResponse):
        super().__init__(msg)
        self.response: ClientResponse = response


class WWWAuthenticateNotInHeadersError(HTTPNTLMExtractionError):
    def __init__(self, response: ClientResponse):
        super().__init__(msg='No WWW-Authenticate header in response.', response=response)


class NoNTLMAuthenticationTypeError(HTTPNTLMExtractionError):
    def __init__(self, response: ClientResponse):
        super().__init__(msg='No NTLM authentication type in WWW-Authenticate header.', response=response)
