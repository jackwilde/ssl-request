from ssl_request import SSLRequest

# Create a certificate signing request with a new private key (default bit size 2048)
# These are the minimum required values to generate a certificate signing request
request = SSLRequest(
    domain="example.com",
    country="GB",
    state="England",
    locality="Bristol",
    organization="My Organisation Name"
)


# Create a certificate signing request with a new private key and specified bit size
request = SSLRequest(
    domain="example.com",
    country="GB",
    state="England",
    locality="Bristol",
    organization="My Organisation Name",
    key_size=4096
)


# Create a certificate signing request with an existing PEM encoded private key
request = SSLRequest(
    domain="example.com",
    country="GB",
    state="England",
    locality="Bristol",
    organization="My Organisation Name",
    key_path="/path/to/private_key"
)


# Create a certificate signing request with an existing PEM encoded encrypted private key
request = SSLRequest(
    domain="example.com",
    country="GB",
    state="England",
    locality="Bristol",
    organization="My Organisation Name",
    key_path="/path/to/private_key",
    key_password="SuperSecurePassword"
)


# Create a certificate signing request with addtional domains (SANs)
request = SSLRequest(
    domain="example.com",
    country="GB",
    state="England",
    locality="Bristol",
    organization="My Organisation Name",
    san_list=[
        "example2.com",
        "example3.com",
    ]
)


# Format the key in PEM-encoding
request.key.as_pem()

# Format the csr in PEM-encoding
request.csr.as_pem()

# The above can be used to write out to a file like
with open("example.com.key", "wb") as f:
    f.write(request.key.as_pem())

