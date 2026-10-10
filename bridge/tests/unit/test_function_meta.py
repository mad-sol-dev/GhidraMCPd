from bridge.features.function_meta import function_entry, function_name

LIVE = {  # 0x002AF9C0 on the reference program, as the client parses it
    "Function": "usbd_init_phy_cep at 002af9c0",
    "Signature": "undefined __stdcall usbd_init_phy_cep(void)",
    "Entry": "002af9c0",
    "Body": "002af9c0 - 002afb0f",
}


def test_the_live_answer_yields_name_and_entry():
    assert function_name(LIVE, 0x002AF9C0) == "usbd_init_phy_cep"
    assert function_entry(LIVE) == 0x002AF9C0


def test_a_different_address_is_no_name():
    assert function_name(LIVE, 0x002AF9C4) is None


def test_an_error_line_is_no_name():
    """"Error getting function: x" parses into a one-key dict, not a function."""

    assert function_name({"Error getting function": "boom"}, 0x1000) is None
    assert function_entry({"Error getting function": "boom"}) is None
