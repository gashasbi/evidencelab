class EvidenceLabError(Exception):
    """Base exception."""


class InputFormatError(EvidenceLabError):
    pass


class SchemaError(EvidenceLabError):
    pass


class ValidationError(EvidenceLabError):
    pass
