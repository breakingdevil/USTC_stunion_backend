import stunion
from stunion import app

from flask import *
from flask_login import current_user
import pytest

from datetime import datetime
from unittest.mock import Mock, patch


@pytest.fixture
def client():
    db_fd, stunion.app.config['DATABASE'] = tempfile.mkstemp()
    stunion.app.config['TESTING'] = True
    del stunion.app.config['SERVER_NAME']
    client = stunion.app.test_client()

    with stunion.app.app_context():
        stunion.init_db()

    yield client

    os.close(db_fd)
    os.unlink(stunion.app.config['DATABASE'])


class MockDatetime(datetime):
    fake_now = None

    @classmethod
    def now(cls):
        return cls.fake_now


@patch("stunion.datetime", MockDatetime)
def test_checkTimeLimit():
    MockDatetime.fake_now = datetime(2019, 3, 1, 12)
    assert stunion.checkTimeLimit() is False
    MockDatetime.fake_now = datetime(2019, 3, 8, 12)
    assert stunion.checkTimeLimit() is True
    MockDatetime.fake_now = datetime(2019, 4, 1, 12)
    assert stunion.checkTimeLimit() is False


class MockCASResponse:
    def __init__(self, success, user):
        self.success = success
        self.user = user


"""
@patch("stunion.cas_client")
def test_caslogin(cas):
    with stunion.app.app_context():
        client = stunion.app.test_client()
        cas_login_url = "https://passport.ustc.edu.cn/login"
        cas.get_login_url.return_value = cas_login_url
        response = client.get(url_for("caslogin"))
        assert response.status_code == 302
        assert response.location == cas_login_url

        cas.perform_service_validate.side_effect = Mock(side_effect=Exception())
        cas.perform_service_validate.return_value = None
        response = client.get(url_for("caslogin", ticket="invalid"))
        assert response.status_code == 302
        assert response.location == url_for("index")

        with client:
            cas.perform_service_validate.side_effect = None
            cas.perform_service_validate.return_value = MockCASResponse(True, "PB17061207")
            response = client.get(url_for("caslogin", ticket="valid"))
            assert response.status_code == 302
            assert response.location == url_for("append", _external=True)

            assert current_user.userSchoolNum == "PB17061207"

            cas.perform_service_validate.return_value = MockCASResponse(True, "PB17061208")
            response = client.get(url_for("caslogin", ticket="valid"))
            assert response.status_code == 302
            assert response.location == url_for("append", _external=True)

            assert current_user.userSchoolNum == "PB17061208"
"""
