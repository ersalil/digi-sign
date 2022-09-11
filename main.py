import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from fastapi import FastAPI, Request, Depends, File, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from sse_starlette.sse import EventSourceResponse
from fastapi.middleware.cors import CORSMiddleware
from Crypto import Random
from typing import List

app = FastAPI()

# frontend_url in the config file
origins = ["*"]

@app.get("/keys")
def rsakeys():
    length=1024  
    privatekey = RSA.generate(length)  
    publickey = privatekey.publickey()
    with open("public_key_dsa.pem", "wb") as file:
        file.write(publickey.exportKey('PEM'))
        file.close()
    with open("private_key_dsa.pem", "wb") as file:
        file.write(privatekey.exportKey('PEM'))
        file.close()
    return privatekey, publickey

@app.post('/generate')
def generate_signature(files: List[UploadFile]):
    print("Generating Signature")
    h = SHA256.new(files[1].file.read())
    rsa = RSA.importKey(files[0].file.read())
    signer = PKCS1_v1_5.new(rsa)
    return signer.sign(h)
    # with open(sig_f, 'wb') as f: f.write(signature)

@app.post('/verify')
def verify_signature(files: List[UploadFile]):
    print("Verifying Signature")
    h = SHA256.new(files[1].file.read())
    rsa = RSA.importKey(files[0].file.read())
    signer = PKCS1_v1_5.new(rsa)
    rsp = "Success" if (signer.verify(h, files[2].file.read())) else " Verification Failure"
    return "Verified!"