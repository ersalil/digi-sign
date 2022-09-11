import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from fastapi import FastAPI, Depends, File, UploadFile
from fastapi.responses import StreamingResponse, FileResponse
from Crypto import Random
from typing import List
import zipfile
from io import BytesIO
import uuid, os

app = FastAPI(title="Digital Signature", description="Verify Documents")

origins = ["*"]
keys_path = "keys/"
sig_docs_path = "sig_docs/"

try:
    os.mkdir(keys_path)
    os.mkdir(sig_docs_path)
except FileExistsError:
    # directory already exists
    pass

def create_keys_name():
    id = str(uuid.uuid4())
    return [i + id for i in ["pub_", "priv_"]]

def zipfiles(file_list):
    io = BytesIO()
    zip_filename = "%s.zip" % file_list[0].split("_")[1]
    with zipfile.ZipFile(io, mode='w', compression=zipfile.ZIP_DEFLATED) as zip:
        for fpath in file_list:
            zip.write(keys_path + fpath)
        #close zip
        zip.close()
    return StreamingResponse(
        iter([io.getvalue()]),
        media_type="application/x-zip-compressed",
        headers = { "Content-Disposition":f"attachment;filename=%s" % zip_filename}
    )

@app.get("/keys")
async def rsakeys():
    length=2048  
    privatekey = RSA.generate(length)  
    publickey = privatekey.publickey()
    publickey_name, privatekey_name = create_keys_name()
    with open(keys_path + publickey_name, "wb") as file:
        file.write(publickey.exportKey('PEM'))
        file.close()
    with open(keys_path + privatekey_name, "wb") as file:
        file.write(privatekey.exportKey('PEM'))
        file.close()
    return zipfiles([publickey_name, privatekey_name])

@app.post('/generate')
async def generate_signature(files: List[UploadFile]):
    print("Generating Signature")
    h = SHA256.new(files[1].file.read())
    rsa = RSA.importKey(files[0].file.read())
    signer = PKCS1_v1_5.new(rsa)
    sig_key_name = "sig_"+files[0].filename.split("_")[1]
    with open(sig_docs_path + sig_key_name, 'wb') as f: f.write(signer.sign(h))
    return FileResponse(sig_docs_path + sig_key_name, media_type='application/octet-stream',filename=sig_key_name) 

@app.post('/verify')
async def verify_signature(files: List[UploadFile]):
    print("Verifying Signature")
    h = SHA256.new(files[1].file.read())
    rsa = RSA.importKey(files[0].file.read())
    signer = PKCS1_v1_5.new(rsa)
    rsp = "Success" if (signer.verify(h, files[2].file.read())) else "Verification Failure"
    return rsp