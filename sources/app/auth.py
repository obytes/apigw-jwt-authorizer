import os
import time

import requests
from cachecontrol import CacheControl
from cachecontrol.caches import FileCache
from jose import jwt, jws, jwk, JWTError
from jose.utils import base64url_decode

FIREBASE_JWK_URI = "https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com"
COGNITO_JWK_URI = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EyugkQ3MJ/.well-known/jwks.json"

os.environ["JWT_ISSUER_JWKS_URI"] = FIREBASE_JWK_URI
os.environ["JWT_AUTHORIZED_AUDIENCES"] = "flask-lambda"


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
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not key.verify(message.encode("utf8"), decoded_signature):
            raise JWTError('Signature verification failed')
    return True


def decode(token, verify_expiration=True, authorized_audiences=None):
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if verify_expiration:
        if time.time() > claims['exp']:
            raise JWTError('Token is expired')
    # and the Audience
    if authorized_audiences:
        # OID TOKEN (aud), OAUTH ACCESS TOKEN (client_id)
        aud = claims.get('aud', claims.get('client_id'))
        if not aud:
            raise JWTError('Token does not have aud nor client_id attribute')
        if aud not in authorized_audiences:
            raise JWTError('Token was not issued for this audience')
    # now we can use the claims
    return claims


def verify(token):
    key = get_public_key(token)
    if valid_signature(token, key):
        authorized_audiences = os.environ.get('JWT_AUTHORIZED_AUDIENCES', []).split(',')
        return decode(
            token,
            verify_expiration=True,
            authorized_audiences=authorized_audiences if len(authorized_audiences) else None
        )


def generate_policy(principal, effect, reason=None):
    auth_response = {
        'principalId': principal,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': os.environ.get('AUTHORIZED_APIS', '*').split(',')
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
    token = event['headers'].get('Authorization', event.get("queryStringParameters", {}).get('authorization'))
    policy = check_auth(token)
    return policy


firebase_access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1MjU1NWEyMjM3MWYxMGY0ZTIyZjFhY2U3NjJmYzUwZmYzYmVlMGMiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiU3VwZXIgQWRtaW4iLCJwaWN0dXJlIjoiaHR0cHM6Ly9pbWcyLmZyZWVwbmcuZnIvMjAxODA0MDIvb2d3L2tpc3NwbmctY29tcHV0ZXItaWNvbnMtdXNlci1wcm9maWxlLWNsaXAtYXJ0LXVzZXItYXZhdGFyLTVhYzIwODEwNWMwM2Q2Ljk1NTg5MDYyMTUyMjY2NTQ4ODM3NjkuanBnIiwiZ3JvdXBzIjpbIlVTRVJTIiwiQURNSU5TIl0sImlzcyI6Imh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9mbGFzay1sYW1iZGEiLCJhdWQiOiJmbGFzay1sYW1iZGEiLCJhdXRoX3RpbWUiOjE2MzU5NzA3ODksInVzZXJfaWQiOiJnZjMwZWNpWUtqVkpyQTVYTUhLME5LRGJLZUMyIiwic3ViIjoiZ2YzMGVjaVlLalZKckE1WE1ISzBOS0RiS2VDMiIsImlhdCI6MTYzNTk3MDc4OSwiZXhwIjoxNjM1OTc0Mzg5LCJlbWFpbCI6ImFkbWluQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7ImVtYWlsIjpbImFkbWluQGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.U7zqYBKG1-_pTGfyWUEk28QvZgivPTywkNsKVAriY64NuAjRQQ9s24l_0hnYNN54kAG3QhFV-zCOoSt_3MvEuaY3LL6nUzdmQdKYiHO1i0s8pplsKn7ljmSACQeVV7564elArs5yKyaejZHEnRwbjYmFzG6KyyBUUnhiR4w2ujM1m4zHlk8y7_OMrIOu3vVnSGrC5jl5n1MvjJFOlIHStOgcfoQoyZht53W_P_bVrJGWl0323Dm0svdAzZTU62QpebZlzxXH_ixc2vhi4NxROM19QmnEoQWkBfFEtzSh849a0x1wNGVaGG6nN28On8Ay3BbagDSzN01Cio2w04azUg"
cognito_access_token = "eyJraWQiOiIzZUtzR21ldUxuVHV4cWllQnR1Y290cHRLZDF0UEtJRFFTVjN0c0J0UFNvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3ODMzMDRiMS0yMzIwLTQ0ZGItOGY1OC0wOWMzMDM1YTY4NmIiLCJkZXZpY2Vfa2V5IjoidXMtZWFzdC0xXzA4YTkzZTY5LTZjYjEtNDk1Yi05YTZmLTM2MDNkOTc1ZjhkZCIsImNvZ25pdG86Z3JvdXBzIjpbIkFETUlOUyIsIlVTRVJTIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0V5dWdrUTNNSiIsImNsaWVudF9pZCI6IjNxZHA0YWVwdWt1cXY1azdxMGF1cG80ZHJhIiwiZXZlbnRfaWQiOiI1MjNkODY1ZS1iMjRhLTRlZTEtOGNhNi1lYTJjMmM0OTJiNTMiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNjM1OTcyMzE0LCJleHAiOjE2MzU5NzU5MTQsImlhdCI6MTYzNTk3MjMxNCwianRpIjoiNmIwYzkxMzEtOGZlMS00OGUzLWFlNDgtOGIzZTNiOTM1N2RjIiwidXNlcm5hbWUiOiIwYWQ1YjY5Mi04ZjgxLTQ5OTItYjVmZS1kZGVlMDlhZjNhM2IifQ.BV81pPsDsusudJuY0p1Fd2JACVeQZWVD7Prb0oHx7Wkq2P6XvqsoCCZ9exaPaOtSyARsvdXmyoBVejeTKLfwYm3EcoFOHNcJ9lN7EiqYFqWxdCIGV3PC4LRXFvv9uFT08xbfPqDIfRnK3CAwPD77RRrqw3-n5QJeWBeQBjuaNloi-C0-R1bFoJVLAByXXgkGroRgI7AvKIGgl6-tPpV-TjzAyq5nJ_SZrNlJD4T67kDx_C1xkIPRaLx9-5riFqeUeX6buJHQb8RTMh3yMoecvk-pJWvZWHZTBkDvbOr4qUYxzVF9QKEdI6UtYMZZkYzBOSKEQc7_SWHPHz5x3RG9mw"

P = handle({
    "headers": {
        "Authorization": firebase_access_token
    }
}, None)

print(P)
