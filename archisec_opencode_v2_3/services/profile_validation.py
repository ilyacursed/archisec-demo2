"""Shared, storage-independent validation of the demo system profile."""


class ProfileValidationError(ValueError):
    """Expected invalid input, safe to report as an HTTP 400."""

    def __init__(self, code, message, field=None):
        super().__init__(message)
        self.code = code
        self.field = field

    def as_dict(self):
        error = {"error": self.code, "message": str(self)}
        if self.field is not None:
            error["field"] = self.field
        return error


def normalize_profile(profile):
    """Return five canonical fields; defaults apply only to absent keys.

    Unknown keys are ignored. Category strings are preserved verbatim, without
    enum restrictions or coercion. Lists are copied to avoid aliasing input.
    """
    if not isinstance(profile, dict):
        raise ProfileValidationError("object_required", "Profile must be an object.")

    normalized = {}
    system_type = profile.get("system_type", "web")
    if not isinstance(system_type, str):
        raise ProfileValidationError(
            "invalid_profile", "system_type must be a string.", "system_type"
        )
    normalized["system_type"] = system_type

    for field in ("interfaces", "data_classes"):
        value = profile.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ProfileValidationError(
                "invalid_profile", f"{field} must be a list of strings.", field
            )
        normalized[field] = list(value)

    for field in ("internet_exposed", "uses_ai"):
        value = profile.get(field, False)
        if not isinstance(value, bool):
            raise ProfileValidationError(
                "invalid_profile", f"{field} must be a boolean.", field
            )
        normalized[field] = value

    return normalized
