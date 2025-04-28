import base64
import datetime
import rsa

# Load private key
with open("private_key.pem", "rb") as key_file:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(key_file.read())

# CloudFront Key Pair ID
KEY_PAIR_ID = "K2HJSD6THIMGN7"

def generate_signed_url(url, expire_minutes=300):
    expire_time = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)).timestamp())

    policy = f'''{{"Statement":[{{"Resource":"{url}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{expire_time}}}}}}}]}}'''

    signature = rsa.sign(policy.encode('utf-8'), PRIVATE_KEY, 'SHA-1')
    signature_encoded = base64.b64encode(signature)
    signature_encoded = signature_encoded.replace(b'+', b'-').replace(b'=', b'_').replace(b'/', b'~')

    signed_url = f"{url}?Expires={expire_time}&Signature={signature_encoded.decode()}&Key-Pair-Id={KEY_PAIR_ID}"
    return signed_url