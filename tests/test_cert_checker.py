from unittest.mock import patch
from certchecker.cert_checker import CertChecker

class TestCase:

    @classmethod
    def setup_class(cls):
        """ TODO implement properly """
        pass
    
    @classmethod
    def teardown_class(cls):
        """ TODO """
        pass

    @patch("certchecker.cert_checker.CertChecker")
    def test_issuer(self, mocked_checker):
        parsed_certificate = {
            "issuer": {"C": "US", "CN": "GTS CA 1O1", "O": "Google Trust Services"}
        }
        expected_issuer = {"commonName": "GTS CA 1O1","country": "US",
            "organisationName": "Google Trust Services"}
        mocked_checker.return_value.parse_certificate.return_value\
            = parsed_certificate
        test_checker = CertChecker("google.com")
        assert test_checker.issuer == expected_issuer
