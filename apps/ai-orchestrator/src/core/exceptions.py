"""Project exceptions."""
from __future__ import annotations


class VigixError(Exception):
    """Base class."""


class ToolFailure(VigixError):
    """A tool could not answer (error / timeout / rate limit). Do not treat this as a negative result."""


class ValidationFailed(VigixError):
    """AI output failed validation."""


class ActionNotAllowed(VigixError):
    """A plan contains an action the procedure does not allow."""


class PermissionDenied(VigixError):
    """The caller's role may not do this."""
