import pytest


class TestHealth:
    @staticmethod
    @pytest.mark.parametrize("url", ["/", "/health/"])
    def test_get_health(client, url):
        resp = client.get(url)

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
