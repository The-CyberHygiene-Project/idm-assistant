from probe.padding import CHARS_PER_TOKEN, padding


def test_zero_is_empty():
    assert padding(0) == ""


def test_size_is_close_to_target():
    for t in (1000, 4000, 15000):
        n = len(padding(t)) / CHARS_PER_TOKEN
        assert 0.95 * t <= n <= 1.05 * t


def test_deterministic():
    assert padding(4000) == padding(4000)


def test_looks_like_reference_material_not_instructions():
    text = padding(2000)
    assert "kanidm" in text.lower() and "call" not in text.lower()
