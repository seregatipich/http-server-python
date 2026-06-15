"""Concrete identifier generator adapter backed by UUID4."""

import uuid


class Uuid4IdGenerator:  # pylint: disable=too-few-public-methods
    """Identifier port implementation producing random UUID4 strings."""

    def new_id(self) -> str:
        """Return a new random UUID4 identifier as a string."""
        return str(uuid.uuid4())
