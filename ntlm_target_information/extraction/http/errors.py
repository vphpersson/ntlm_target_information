from httpx import Response

from ntlm_target_information.errors import ExtractionError


class HTTPNTLMExtractionError(ExtractionError):
    def __init__(self, msg: str, response: Response):
        super().__init__(msg)
        self.response: Response = response


class WWWAuthenticateNotInHeadersError(HTTPNTLMExtractionError):
    def __init__(self, response: Response):
        super().__init__(msg='No WWW-Authenticate header in response.', response=response)


class NoNTLMAuthenticationTypeError(HTTPNTLMExtractionError):
    def __init__(self, response: Response):
        super().__init__(msg='No NTLM authentication type in WWW-Authenticate header.', response=response)
