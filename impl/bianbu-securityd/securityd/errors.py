"""D-Bus 错误码域（API §1）与异常类型。"""
from __future__ import annotations

ERROR_DOMAIN = "io.bianbu.Error"


class SecurityError(Exception):
    """securityd 基异常，携带 D-Bus 错误名。"""

    dbus_error_name = f"{ERROR_DOMAIN}.Internal"

    def __init__(self, message: str = ""):
        super().__init__(message)
        self.message = message


class PermissionDenied(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.PermissionDenied"


class ConfirmRequired(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.ConfirmRequired"


class QuotaExceeded(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.QuotaExceeded"


class InvalidManifest(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.InvalidManifest"


class AuditFailure(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.AuditFailure"


class SandboxBuildFailed(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.SandboxBuildFailed"


class NotFound(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.NotFound"


class InvalidArgument(SecurityError):
    dbus_error_name = f"{ERROR_DOMAIN}.InvalidArgument"
