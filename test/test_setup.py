import setup


def test_setup():
    assert isinstance(setup.bind, str)
    assert setup.bind
