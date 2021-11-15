import os
import time

import requests
from cachecontrol import CacheControl
from cachecontrol.caches import FileCache
from jose import jwt, jws, jwk, JWTError
from jose.utils import base64url_decode

FIREBASE_JWK_URI = "https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com"


def search_for_key(token, keys, construct=True):
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers["kid"]
    # search for the kid in the downloaded public keys
    key = list(filter(lambda k: k["kid"] == kid, keys))
    if not key:
        raise JWTError(f"Public key not found in jwks.json")
    else:
        key = key[0]
    if construct:
        return jwk.construct(key)
    else:
        return key


def get_public_key(token):
    """
    Because Google's public keys are only changed infrequently (on the order of once per day),
    we can take advantage of caching to reduce latency and the potential for network errors.
    """
    jwks_uri = os.environ["JWT_ISSUER_JWKS_URI"]
    sess = CacheControl(requests.Session(), cache=FileCache("/tmp/jwks-cache"))
    request = sess.get(jwks_uri)
    ks = request.json()
    keys = []
    #
    if jwks_uri == FIREBASE_JWK_URI:
        for k, v in ks.items():
            keys.append({
                "alg": "RS256",
                "kid": k,
                "pem": v
            })
        return search_for_key(token, keys, construct=False)
    else:
        keys = ks["keys"]
        return search_for_key(token, keys, construct=True)


def valid_signature(token, key):
    if isinstance(key, dict):
        # verify the signature, exception should be thrown if verification failed
        jws.verify(token, key["pem"], [key["alg"]], verify=True)
    else:
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
        # verify the signature
        if not key.verify(message.encode("utf8"), decoded_signature):
            raise JWTError("Signature verification failed")
    return True


def decode(token, verify_expiration=True, authorized_audiences=None):
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if verify_expiration:
        if time.time() > claims["exp"]:
            raise JWTError("Token is expired")
    # and the Audience
    if authorized_audiences:
        # OID TOKEN (aud), OAUTH ACCESS TOKEN (client_id)
        aud = claims.get("aud", claims.get("client_id"))
        if not aud:
            raise JWTError("Token does not have aud nor client_id attribute")
        if aud not in authorized_audiences:
            raise JWTError("Token was not issued for this audience")
    # now we can use the claims
    return claims


def verify(token):
    key = get_public_key(token)
    if valid_signature(token, key):
        authorized_audiences = os.environ.get("JWT_AUTHORIZED_AUDIENCES", []).split(",")
        return decode(
            token,
            verify_expiration=os.environ.get("JWT_VERIFY_EXPIRATION", "true") == "true",
            authorized_audiences=authorized_audiences if len(authorized_audiences) else None
        )


def generate_policy(principal, effect, reason=None):
    auth_response = {
        "principalId": principal,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": os.environ.get("AUTHORIZED_APIS", "*").split(",")
                }
            ]
        }
    }
    if reason:
        auth_response.update({
            'context': {
                'error': reason
            }
        })
    return auth_response


def check_auth(token):
    if not token:
        return generate_policy("rogue", "Deny", reason="Missing Access Token")
    try:
        claims = verify(token)
        if claims:
            return generate_policy(claims["sub"], "Allow")
    except Exception as e:
        return generate_policy("rogue", "Deny", reason=str(e))


def handle(event, context):
    print(event)
    token = event["headers"].get("Authorization", event.get("queryStringParameters", {}).get("authorization"))
    policy = check_auth(token)
    print(policy)
    return policy
