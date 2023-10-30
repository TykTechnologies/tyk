from tests.base import Base
import pytest

@pytest.mark.gw
class TestGatewayHotReload(Base):

    def test_gateway_hot_reload(self):
        """
        Test for Gateway hot reload
        """
        print(self.gateway_secret)
        url = self.gateway_url + 'tyk/reload/'
        r = self.request.get(url, headers=self.gateway_secret)
        if r.status_code != 200:
            self.fail(msg=r.text)
        else:
            self.json_print(r.json())

