import hashlib
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Sequence
from hmac import HMAC, compare_digest
from random import randint


class InvalidTokenError(Exception):
    """
    Raised during verification when the token itself is malformed.
    """


class InvalidSignatureError(Exception):
    """
    Raised during verification if the token has an invalid signature.
    """


class Token(str):
    """
    Wrapper type for signed tokens, which are just strings,
    but this will help make their purpose clear in the code.
    """


class TokenSigner:
    _signing_keys: Sequence[bytes]

    def __init__(self, signing_keys: Sequence[bytes]):
        self._signing_keys = signing_keys
        self._num_signing_keys = len(signing_keys)
        if self._num_signing_keys == 0:
            raise ValueError("signing_keys must include at least one key")

    def sign(self, payload: bytes | str, payload_str_encoding: str = "utf-8") -> Token:
        normalized_payload = (
            payload.encode(payload_str_encoding)
            if isinstance(payload, str)
            else payload
        )
        key_index = randint(0, self._num_signing_keys - 1)
        key = self._signing_keys[key_index]
        hmac = HMAC(key=key, msg=normalized_payload, digestmod=hashlib.sha256)
        digest = hmac.digest()

        combined = key_index.to_bytes(1) + digest + normalized_payload
        return Token(urlsafe_b64encode(combined).decode("ascii"))

    def verify(self, token: Token) -> bytes:
        try:
            decoded = urlsafe_b64decode(token)
        except ValueError as e:
            raise InvalidTokenError() from e

        if len(decoded) < 34:
            raise InvalidTokenError()

        key_index = decoded[0]
        if key_index >= self._num_signing_keys:
            raise InvalidTokenError

        key = self._signing_keys[key_index]
        digest = decoded[1:33]
        payload = decoded[33:]
        hmac = HMAC(key=key, msg=payload, digestmod=hashlib.sha256)
        recalculated_digest = hmac.digest()
        if compare_digest(digest, recalculated_digest):
            return payload
        else:
            raise InvalidSignatureError()
