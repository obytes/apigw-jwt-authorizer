import json
from pprint import pprint

import requests
from jose import jwk

user_pool_id = "us-east-1_EyugkQ3MJ"


def generate_pub_keys():
    public_keys = []
    response = requests.get(
        f"https://cognito-idp.{user_pool_id.split('_')[0]}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    )
    keys = response.json()["keys"]
    for key in keys:
        public_keys.append({
            'pem': jwk.construct(key).to_pem().decode("utf8"),
            'alg': key['alg']
        })
    return {
        'public_keys': public_keys
    }


if __name__ == "__main__":
    print(json.dumps(generate_pub_keys(), indent=1))
