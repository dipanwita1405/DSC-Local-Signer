# File: local_signer.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pkcs11
from pkcs11 import ObjectClass, Attribute

app = FastAPI()

# Frappe Cloud Cross-Origin Requests allow karne ke liye
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production me exact domain likh sakte hain (e.g. "https://yourcompany.frappe.cloud")
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignPayload(BaseModel):
    hash: str
    pin: str

@app.post("/sign")
def sign_hash_payload(payload: SignPayload):
    possible_dlls = [
        r"C:\Windows\System32\eps2003csp11v2.dll",
        r"C:\Windows\System32\ep2000pk11.dll",
        r"C:\Windows\System32\ePS2003csp11.dll"
    ]
    
    dll_path = next((p for p in possible_dlls if os.path.exists(p)), None)
    if not dll_path:
        raise HTTPException(status_code=500, detail="USB Token Driver (DLL) system mein nahi mila!")

    try:
        lib = pkcs11.lib(dll_path)
        slots = lib.get_slots(token_present=True)
        if not slots:
            raise HTTPException(status_code=400, detail="USB Token PC se connected nahi hai!")

        token = slots[0].get_token()
        
        with token.open(user_pin=payload.pin) as session:
            priv_keys = list(session.get_objects({ObjectClass.PRIVATE_KEY: True}))
            if not priv_keys:
                raise HTTPException(status_code=404, detail="Token ke andar Private Key nahi mili!")
            
            key = priv_keys[0]
            raw_hash = bytes.fromhex(payload.hash)
            
            # Hardware Level Crypto Signature
            signature = key.sign(raw_hash)
            return {"status": "success", "signature": signature.hex()}

    except pkcs11.exceptions.PinIncorrect:
        raise HTTPException(status_code=401, detail="Galat PIN enter kiya gaya hai!")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Local HTTPS Service on Port 39999
    uvicorn.run(app, host="127.0.0.1", port=39999, ssl_keyfile="key.pem", ssl_certfile="cert.pem")