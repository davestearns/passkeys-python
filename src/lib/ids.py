import secrets
import string
from typing import Final, Type

import uuid_utils as uuid


class BaseID(str):
    """
    Abstract base class for all prefixed ID types.

    To define a new ID type, create a class that inherits from
    `BaseID`, and set its `PREFIX` class variable to a string
    value that is unique across all BaseID subclasses.

    Example:
        >>> class TestID(BaseID):
        ...     PREFIX = "test"

    If the PREFIX value is not unique across all subclasses
    of BaseID, a ValueError will be raised when the class is
    created.

    To generate a new ID, just create a new instance of your
    derived class with no arguments:

    Example:
        >>> id = TestID()

    The value of the new `id` will have the form
    `"{PREFIX}_{uuid7-in-base36}"`. UUIDv7 values start with
    a timestamp so they have a natural creation ordering. The
    UUID is encoded in base36 instead of hex (base16) to keep
    it shorter.

    The `id` will be typed as a `TestID`, but since it inherits
    from `BaseID` and that inherits from `str`, you can treat
    `id` as a string. Database libraries and other encoders
    will also see it as a string, so it should work seamlessly.

    To rehydrate a string ID back into a `TestID`, pass it
    to the constructor as an argument:

    Example:
        >>> rehydrated_id = TestID(encoded_id)

    A `ValueError` will be raised if `encoded_id` doesn't have
    the right prefix.

    If you have a string ID but aren't sure what type it is,
    use `BaseID.parse()` to parse it into the appropriate type.

    Example:
        >>> parsed_id = BaseID.parse(encoded_id)

    You can then test the `type(parsed_id)` to determine
    which type it is.

    author: Dave Stearns <https://github.com/davestearns>
    """

    PREFIX_SEPARATOR: Final = "_"
    ALPHABET: Final = string.digits + string.ascii_lowercase
    ALPHABET_LEN: Final = len(ALPHABET)

    PREFIX: str
    """
    Each derived class must set PREFIX to a unique string.
    """

    ORDERED: bool = True
    """
    When set to True, new IDs will start with a timestamp,
    so they have a natural creation ordering. If you instead
    want a totally random ID set this to False. Random IDs are
    good for situations where you're using the ID as an
    authorization token, so you need it to be unguessable.
    """

    prefix_to_class_map: dict[str, Type["BaseID"]] = {}

    def __new__(cls, encoded_id: str | None = None):
        if encoded_id is None:
            # Generate a new UUID
            id_int = uuid.uuid7().int if cls.ORDERED else secrets.randbits(128)

            # Base36 encode it
            encoded_chars = []
            while id_int > 0:
                id_int, remainder = divmod(id_int, cls.ALPHABET_LEN)
                encoded_chars.append(cls.ALPHABET[remainder])
            encoded = "".join(reversed(encoded_chars))

            # Build the full prefixed ID and initialize str with it
            prefixed_id = f"{cls.PREFIX}{cls.PREFIX_SEPARATOR}{encoded}"
            return super().__new__(cls, prefixed_id)
        else:
            # Validate encoded_id
            expected_prefix = cls.PREFIX + cls.PREFIX_SEPARATOR
            if not encoded_id.startswith(expected_prefix):
                raise ValueError(
                    f"Encoded ID {encoded_id} does not have expected prefix {cls.PREFIX}"
                )
            return super().__new__(cls, encoded_id)

    def __repr__(self) -> str:
        """
        Returns the detailed representation, which include the specific
        ID class name wrapped around the string ID value.
        """
        return f"{self.__class__.__name__}('{self.__str__()}')"

    def __init_subclass__(cls):
        """
        Called when new subclasses are initialized. This is where we ensure
        that the PREFIX value on a new subclass is unique across the system.
        """
        if not hasattr(cls, "PREFIX"):
            raise AttributeError(
                "ID classes must define a class property named"
                "`PREFIX` set to a unique prefix string."
            )
        if cls.PREFIX in cls.prefix_to_class_map:
            raise ValueError(
                f"The ID prefix '{cls.PREFIX}' is used on both"
                f" {cls.prefix_to_class_map[cls.PREFIX]} and {cls}."
                " ID prefixes must be unique across the set of all ID classes."
            )
        cls.prefix_to_class_map[cls.PREFIX] = cls
        return super().__init_subclass__()

    @classmethod
    def parse(cls, encoded_id: str) -> "BaseID":
        """
        Parses an string ID of an unknown type into the appropriate
        class ID instance. If the prefix does not match any of the
        registered ones, this raises `ValueError`.
        """
        for prefix, cls in cls.prefix_to_class_map.items():
            if encoded_id.startswith(prefix):
                return cls(encoded_id)

        raise ValueError(
            f"The prefix of ID '{encoded_id}' does not match a known ID prefix."
        )
