from tests.base import Base
import pytest

@pytest.mark.gw
class TestHelloEndpoint(Base):

    @pytest.mark.gw
    def test_hello_endpoint(self):
        """
        Test for Hello endpoint on gateway (healthcheck)
        """
        url = self.gateway_url + 'hello'
        r = self.request.get(url)
        self.assertEqual(200, r.status_code, msg="Bad response code")
        self.assertEqual(4, len(r.json()), msg="Wrong response in body")
        self.assertIn("status", r.json())
        self.assertIn("details", r.json())
        self.json_print(r.json())

