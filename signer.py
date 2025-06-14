import base64
import datetime
import rsa
import os
from urllib.parse import urlparse, urlunparse

PRIVATE_KEY_PATH = "~/private_key.pem"
PRIVATE_KEY_PATH = os.path.expanduser(PRIVATE_KEY_PATH)

# CloudFront Key Pair ID
KEY_PAIR_ID = "KSX65MV722Q6F"

def clean_url(url):
    """Remove any existing query parameters"""
    parsed = urlparse(url)
    cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
    return cleaned

with open(PRIVATE_KEY_PATH, "rb") as key_file:
    key_data = key_file.read()

try:
    # First try loading as PKCS#1 (RSA PRIVATE KEY)
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(key_data)
except ValueError:
    # If failed, assume PKCS#8 (PRIVATE KEY) and decode
    from Crypto.PublicKey import RSA as CryptoRSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA1

    # Parse PKCS#8 private key
    PRIVATE_KEY = CryptoRSA.import_key(key_data)

def generate_signed_url(url, expire_minutes=300):
    # Clean old query parameters
    clean = clean_url(url)

    expire_time = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)).timestamp())
    policy = f'''{{"Statement":[{{"Resource":"{clean}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{expire_time}}}}}}}]}}'''

    policy_bytes = policy.encode('utf-8')

    if isinstance(PRIVATE_KEY, rsa.PrivateKey):
        signature = rsa.sign(policy_bytes, PRIVATE_KEY, 'SHA-1')
    else:
        hash_obj = SHA1.new(policy_bytes)
        signature = pkcs1_15.new(PRIVATE_KEY).sign(hash_obj)

    signature_encoded = base64.b64encode(signature)
    signature_encoded = signature_encoded.replace(b'+', b'-').replace(b'=', b'_').replace(b'/', b'~')

    separator = "&" if "?" in clean else "?"
    signed_url = f"{clean}{separator}Expires={expire_time}&Signature={signature_encoded.decode()}&Key-Pair-Id={KEY_PAIR_ID}"
    return signed_url
