# bridge/tests/unit/test_optional_adapters.py
import pytest
from bridge.adapters import load_optional_adapter

def test_unknown_optional_adapter_raises_value_error():
    with pytest.raises(ValueError) as e:
        load_optional_adapter("mips")
    msg = str(e.value).lower()
    assert "unknown optional adapter" in msg
    assert "available" in msg
