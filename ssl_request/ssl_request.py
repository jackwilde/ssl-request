from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Outer class for SSL certificate request
class SSLRequest:
    def __init__(self, domain:str, country:str, state:str, locality:str,
                 organization:str, san_list:list=None, key_path:str=None, key_password=None, key_size:int=2048):
        """
        Generates an SSL certificate request
        :param domain: Fully qualified domain name
        :param country: Country code
        :param state: State or Area
        :param locality: City
        :param organization: Organization name
        :param san_list: List of additional fully qualified domain names
        :param key_path: Path to existing PEM encoded private key
        :param key_password: Password for existing PEM encoded private key
        :param key_size: Size in bits for generated private key
        """
        self.domain = domain

        # Set key using Key class
        self.key = self.Key(
            key_path=key_path,
            key_password=key_password,
            key_size=key_size,
        )

        # Set csr using Csr class
        self.csr = self.Csr(
            domain=self.domain,
            key=self.key,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            san_list=san_list
        )

    # Inner class Key
    class Key:
        def __init__(self, key_path, key_size, key_password):
            """
            Creates an RSA key object
            :param key_path: Path to existing PEM encoded private key
            :param key_size: Size in bits for generated private key
            :param key_password: Password for existing PEM encoded private key
            """
            # If key_path is supplied set the key to that
            if key_path:
                # Check for key password and encode as utf-8
                if key_password:
                    key_password = key_password.encode("utf-8")

                # Open supplied key file and convert to key object
                with open(key_path, "rb") as f:
                    try:
                        self.private_key = serialization.load_pem_private_key(
                            f.read(),
                            password=key_password,
                        )
                    except ValueError as e:
                        raise SystemExit(e)
                    except TypeError as e:
                        raise SystemExit(e)

            # If key_path not supplied then generate a new key object
            else:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )

        def as_pem(self):
            """
            Converts the private key into PEM encoded format
            :return: PEM-encoded private key
            """
            return self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

        def __str__(self):
            """
            Prints the private key in PEM encoded format
            :return: PEM-encoded private key
            """
            return self.as_pem().decode('utf-8')


    # Inner class Csr
    class Csr:
        def __init__(self, domain, key, country, state, locality, organization, san_list):
            """
            Creates an CSR object
            :param domain: Fully qualified domain name
            :param key: Private key object
            :param country: Country code
            :param state: State or Area
            :param locality: City
            :param organization: Organization name
            :param san_list: List of additional fully qualified domain names
            """
            # Create a CSR builder with subject attributes
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]))

            # Add SANs to builder if provided
            if san_list:
                dns_list = [x509.DNSName(domain) for domain in san_list]
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(dns_list),
                    critical=False,
                )

            # Generate CSR by signing with the private key
            self.csr = builder.sign(key.private_key, hashes.SHA256())

        def as_pem(self):
            """
           Converts the certificate signing request into PEM encoded format
           :return: PEM-encoded certificate signing request
           """
            return self.csr.public_bytes(serialization.Encoding.PEM)


        def __str__(self):
            """
            Prints the certificate signing request into PEM encoded format
            :return: PEM-encoded certificate signing request
            """
            return self.as_pem().decode('utf-8')
