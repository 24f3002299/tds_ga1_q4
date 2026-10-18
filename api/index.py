from fastapi import FastAPI, Response, status
from pydantic import BaseModel
import jwt

app = FastAPI()

# Your assigned validation values
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-1dj29omv.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ok0HspNjga+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSe1bvbYGuc3EbNy4xFyF5Cbj5DHJMID
EkrYOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVN1du6A9cNteNpXc
WyJjG2axVfmq7i6SukR1JoWYG7xTTAvKPujS14OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd119VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4L1gniT7G1kL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(req: TokenRequest, response: Response):
    try:
        # jwt.decode automatically verifies the signature, issuer, audience, and expiry
        decoded = jwt.decode(
            req.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE
        )
        
        # On valid token: respond 200 with required payload[cite: 47]
        return {
            "valid": True,
            "email": decoded.get("email", ""),
            "sub": decoded.get("sub", ""),
            "aud": decoded.get("aud", "")
        }
        
    except Exception:
        # On any invalid token (tampered, expired, wrong aud/iss): respond 401 Unauthorized with valid: false[cite: 47]
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"valid": False}