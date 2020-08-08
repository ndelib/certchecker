from unittest.mock import patch, MagicMock
from certchecker.cert_checker import CertChecker



class TestCase:

    @classmethod
    def setup_class(cls):
        """ TODO """
        pass

    @classmethod
    def teardown_class(cls):
        """ TODO """
        pass

    def test_issuer(self):
        expected_issuer = {"commonName": "GTS CA 1O1","country": "US",
            "organisationName": "Google Trust Services"}
        # Given a dummy Google cert, ensure we extract the correct issuer
        with patch.object(CertChecker, "_get_certificate", \
            return_value=self._get_mocked_cert("google.com")):
            test_checker = CertChecker("google.com")
            assert test_checker.issuer == expected_issuer

    def _get_mocked_cert(self, host):
        data_files = {
            "google.com": "tests/data/dummy_google_cert.pem"
        }
        dummy_cert = ""
        with open(data_files[host], "r") as mock_data:
            dummy_cert = mock_data.read()
        return dummy_cert



