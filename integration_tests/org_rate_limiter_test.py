from tests.base import Base
import pytest

@pytest.mark.gw
class OrgRateLimits(Base):

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        self.url = self.gateway_url + 'tyk/org/keys/'
        self.authorization = self.create_user("test123")
        self.header = {'authorization': self.authorization}
        self.api_id = self.create_api(self.header)
        self.org_id = self.get_organization_id()
        self.request.headers.update(self.gateway_secret)

        yield   # This is where the test case runs

        self.clear_all(self.header)
        self.request.close()

    def test_add_organization_limits(self):
        """
        Test for add organization limit
        """
        obj = {
            "rate": 10,
            "per": 60,
            "allowance": 10,
            "quota_max": 60,
            "quota_renews": 1522083671,
            "quota_remaining": 60,
            "quota_renewal_rate": 3600,
            "data_expires": 600,
            "org_id": self.org_id
        }
        r = self.request.post(self.url + self.org_id, json=obj)
        assert r.status_code == 200, r.text
        assert self.org_id == r.json()['key'], 'Wrong key id in response'

    def test_delete_organization_limits(self):
        """
        Test for delete organization limit
        """
        obj = {
            "rate": 10,
            "per": 60,
            "allowance": 10,
            "quota_max": 60,
            "quota_renews": 1522083671,
            "quota_remaining": 60,
            "quota_renewal_rate": 3600,
            "data_expires": 600,
            "org_id": self.org_id
        }
        r = self.request.post(self.url + self.org_id, json=obj)
        assert r.status_code == 200, r.text
        assert self.org_id == r.json()['key'], 'Wrong key id in response'
        
        d = self.request.delete(self.url + self.org_id)
        assert d.status_code == 200, d.text
        self.json_print(d.json())
