""" CertChecker
"""

import ssl
import socket
import OpenSSL
from datetime import datetime


class CertChecker:
    """ Gets TLS certificate of target server and parses key information. """

    def __init__(self, target_server):
        self._certificate = self._get_certificate(target_server)
        self.parsed_certificate = self._parse_certificate(self._certificate)

    @property
    def issuer(self):
        """ Returns CA issuer information.
        :return: Dictionary of the form:
            {'country': <issuer_country>,
             'commonName': <common_name>,
             'organisationName': <organisation_name>}
        """

        issuer_dict = {}
        issuer_info = self.parsed_certificate['issuer']

        def _full_field_name(short_name):
            mapping = {'C': 'country', 'CN': 'commonName',
                       'O': 'organisationName'}
            mapped_name = mapping.get(short_name, short_name)
            return mapped_name

        # Expand field names to longer, more-human readable version
        # i.e. 'CN' -> 'commonName'
        for field_name, field_val in issuer_info.items():
            short_name = self._ensure_utf8(field_name)
            field_val = self._ensure_utf8(field_val)
            full_field = _full_field_name(short_name)
            issuer_dict[full_field] = field_val
        return issuer_dict

    def get_ca_chain(self):
        """ TODO """
        pass

    def _get_certificate(self, host, port=443, timeout=10):
        """ """

        # Get remote host's TLS certificate in DER format
        ssl_context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) \
                as secure_sock:
                secure_sock.settimeout(timeout)
                cert_der = secure_sock.getpeercert(True)
        # Convert to PEM format and return
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        return cert_pem

    def _parse_certificate(self, certificate):
        """ """

        # Load x509 TLS certificate
        cert_filetype = OpenSSL.crypto.FILETYPE_PEM
        cert_x509 = OpenSSL.crypto.load_certificate(cert_filetype,\
            certificate)

        # Get expiration before / after values
        timestamp_format = '%Y%m%d%H%M%SZ'
        invalid_before = cert_x509.get_notBefore()
        invalid_before = datetime.strptime(self._ensure_utf8(invalid_before),\
            timestamp_format)
        invalid_after = cert_x509.get_notAfter()
        invalid_after = datetime.strptime(self._ensure_utf8(invalid_after),\
            timestamp_format)

        # Stick fields of interest into a dictionary and return
        parsed_cert = {
            'issuer': dict(cert_x509.get_issuer().get_components()),
            'subject': dict(cert_x509.get_subject().get_components()),
            'version': cert_x509.get_version(),
            'serialNumber': cert_x509.get_serial_number(),
            'invalidBefore': invalid_before,
            'invalidAfter': invalid_after,
        }
        return parsed_cert

    def _ensure_utf8(self, target_str):
        if not isinstance(target_str, str):
            # Convert from bytes instance to string
            target_str = str(target_str, "utf-8")
        return target_str


def tmp_test():
    
    google_cert = CertChecker("google.com")
    from pprint import pprint
    pprint(google_cert.issuer)
    pprint(google_cert.parsed_certificate)

if __name__ == "__main__":
    tmp_test()