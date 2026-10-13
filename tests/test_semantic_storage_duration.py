from evidencelab.models import Node
from evidencelab.semantics import _derive_storage


def test_global_placeholder_is_not_automatic():
    node = Node(
        "global-buffer",
        "LOCAL",
        {
            "name": "buffer",
            "code": "<global> buffer",
            "typeFullName": "char[32]",
        },
    )

    derived = _derive_storage(node)

    assert derived["storage_duration"] == "STATIC_GLOBAL"
    assert derived["stack_candidate"] is False
    assert derived["physical_stack_region"] == "UNKNOWN"


def test_regular_local_array_remains_automatic():
    node = Node(
        "local-buffer",
        "LOCAL",
        {
            "name": "buffer",
            "code": "char buffer[32]",
            "typeFullName": "char[32]",
        },
    )

    derived = _derive_storage(node)

    assert derived["storage_duration"] == "AUTOMATIC"
    assert derived["stack_candidate"] is True


def test_static_local_array_remains_static():
    node = Node(
        "static-local-buffer",
        "LOCAL",
        {
            "name": "buffer",
            "code": "static char buffer[32]",
            "typeFullName": "char[32]",
        },
    )

    derived = _derive_storage(node)

    assert derived["storage_duration"] == "STATIC_LOCAL"
    assert derived["stack_candidate"] is False
