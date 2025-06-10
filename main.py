# -*- coding: utf-8 -*-
"""
 @Author: xiaoxuan6
 @Date: 2025/6/3 13:15
 @File: main.py
 @Description: 
"""
import binascii
import json
import os
import random
import time

import ddddocr
import requests
import uvicorn
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fake_useragent import UserAgent
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


class DecryptRequest(BaseModel):
    hash: str = None
    sign: str = None


class ApiResponse(BaseModel):
    success: bool
    result: str = None


async def encode(hash, t):
    data = {
        "timestamp": t,
        "hash": hash
    }
    e = json.dumps(data, separators=(',', ':'))
    n = str(t).encode('utf-8')

    # CryptoJS 不截断超长key，pycryptodome会报错，需处理
    if len(n) < 16:
        n = n.ljust(16, b'\0')
    elif len(n) > 16:
        n = n[:16]

    cipher = AES.new(n, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(e.encode('utf-8'), AES.block_size))
    # CryptoJS 默认输出 ciphertext 为16进制字符串（不是base64）
    return binascii.hexlify(ct_bytes).decode('utf-8')


async def decrypt_captcha(img: str):
    ocr = ddddocr.DdddOcr(show_ad=False, beta=True)
    return ocr.classification(open(img, 'rb').read())


async def pmd5(hash: str):
    se = requests.session()

    headers = {
        'user-agent': UserAgent().chrome,
    }

    se.get("https://pmd5.com")
    while True:
        captcha_img = se.get(f"https://api.pmd5.com/pmd5api/checkcode?_{random.random()}", headers=headers).content
        with open('captcha.png', 'wb') as f:
            f.write(captcha_img)

        text = decrypt_captcha('captcha.png')
        if len(text) == 4:
            os.remove('captcha.png')
            response = se.get(f"https://api.pmd5.com/pmd5api/pmd5?checkcode={text}&pwd={hash}", headers=headers).json()
            if response['code'] == 0:
                result = response['result'][hash] if response['result'] is not None else '解密失败'
                success = True if response['result'] is not None else False
                return ApiResponse(success=success, result=result)
            else:
                return ApiResponse(success=False, result='解密失败')


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")


@app.get('/')
async def index():
    return FileResponse('index.html')


@app.post('/api/decrypt', response_model=ApiResponse)
async def decrypt(request: DecryptRequest):
    try:
        hash = request.hash
        if len(hash) != 32:
            return ApiResponse(success=False, result='请输入正确的MD5字符串')

        sign = request.sign
        if sign is None or len(sign) == 0:
            return ApiResponse(success=False, result='sign 不能为空')

        _sign = str(sign).split("|")
        if int(time.time() * 1000) - int(_sign[1]) > 50:
            return ApiResponse(success=False, result='sign 已过期')

        if _sign[0] != encode(hash, str(_sign[1])):
            return ApiResponse(success=False, result='无效的 sign')

        return pmd5(hash)
    except Exception as e:
        return {"success": False, "detail": str(e)}


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
