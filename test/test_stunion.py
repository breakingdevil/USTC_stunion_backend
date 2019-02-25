import stunion

from datetime import datetime
from unittest.mock import patch


@patch("datetime.datetime.now")
def test_checkTimeLimit(now):
    now.return_value = datetime(2019, 3, 1, 12)
    assert stunion.checkTimeLimit() is False
    now.return_value = datetime(2019, 3, 8, 12)
    assert stunion.checkTimeLimit() is True
    now.return_value = datetime(2019, 4, 1, 12)
    assert stunion.checkTimeLimit() is False
