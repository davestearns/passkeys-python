from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Sequence
from typing import Generator

import pytest

from .tokens import InvalidSignatureError, InvalidTokenError, Token, TokenSigner


@pytest.fixture
def keys() -> Generator[Sequence[bytes]]:
    yield [b"key 1", b"key 2", b"key 3"]


@pytest.fixture
def signer(keys: Sequence[bytes]) -> Generator[TokenSigner]:
    yield TokenSigner(keys)


def test_sign_and_verify(signer: TokenSigner) -> None:
    payload = b"test payload"
    token = signer.sign(payload)
    assert len(token) > 0
    verified_payload = signer.verify(token)
    assert verified_payload == payload


def test_sign_and_verify_str_payload(signer: TokenSigner) -> None:
    payload = "test payload"
    token = signer.sign(payload)
    assert len(token) > 0
    verified_payload = signer.verify(token).decode()
    assert verified_payload == payload


def test_invalid_token_raises(signer: TokenSigner) -> None:
    with pytest.raises(InvalidTokenError):
        signer.verify(Token("🤓"))  # not valid base64

    with pytest.raises(InvalidTokenError):
        signer.verify(Token(signer.sign(b"test payload")[0:10]))  # not long enough


def test_tampered_payload_raises(signer: TokenSigner) -> None:
    token = signer.sign(b"test payload")
    decoded = urlsafe_b64decode(token)
    tampered_decoded = decoded[:-1] + (decoded[-1] ^ 1).to_bytes(1)
    tampered_token = urlsafe_b64encode(tampered_decoded).decode("ascii")
    with pytest.raises(InvalidSignatureError):
        signer.verify(Token(tampered_token))


def test_invalid_key_index_raises(signer: TokenSigner) -> None:
    token = signer.sign(b"test payload")
    decoded = urlsafe_b64decode(token)
    invalid_key_index = signer._num_signing_keys
    tampered_decoded = invalid_key_index.to_bytes(1) + decoded[1:]
    tampered_token = urlsafe_b64encode(tampered_decoded).decode("ascii")
    with pytest.raises(InvalidTokenError):
        signer.verify(Token(tampered_token))


def test_tampered_key_index_raises(signer: TokenSigner) -> None:
    token = signer.sign(b"test payload")
    decoded = urlsafe_b64decode(token)
    new_key_index = 1 if decoded[0] == 0 else 0
    tampered_decoded = new_key_index.to_bytes(1) + decoded[1:]
    tampered_token = urlsafe_b64encode(tampered_decoded).decode("ascii")
    with pytest.raises(InvalidSignatureError):
        signer.verify(Token(tampered_token))


def test_tampered_digest_raises(signer: TokenSigner) -> None:
    token = signer.sign(b"test payload")
    decoded = urlsafe_b64decode(token)
    tampered_decoded = decoded[:1] + (decoded[1] ^ 1).to_bytes(1) + decoded[2:]
    tampered_token = urlsafe_b64encode(tampered_decoded).decode("ascii")
    with pytest.raises(InvalidSignatureError):
        signer.verify(Token(tampered_token))


def test_one_key() -> None:
    payload = b"test payload"
    signer = TokenSigner([b"test key"])
    token = signer.sign(payload)
    verified_payload = signer.verify(token)
    assert verified_payload == payload


def test_zero_keys_raises() -> None:
    with pytest.raises(ValueError):
        TokenSigner([])
