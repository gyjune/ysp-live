import base64
import ctypes
import os
import random
import struct
import time
import uuid
import socket
import requests
from construct import Struct, Int16ub, Int32ub, Bytes, this
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, Response
import uvicorn

# ============== 构造体定义 ==============
int16_str_struct = Struct(
    "length" / Int16ub,
    "value" / Bytes(this.length)
)

ckey_struct = Struct(
    "header" / Bytes(12),
    "Platform" / Bytes(4),
    "signature" / Bytes(4),
    "Timestamp" / Bytes(4),
    "Sdtfrom" / int16_str_struct,
    "randFlag" / int16_str_struct,
    "appVer" / int16_str_struct,
    "vid" / int16_str_struct,
    "guid" / int16_str_struct,
    "part1" / Int32ub,
    "isDlna" / Int32ub,
    "uid" / int16_str_struct,
    "bundleID" / int16_str_struct,
    "uuid4" / int16_str_struct,
    "bundleID1"/ int16_str_struct,
    "ckeyVersion" / int16_str_struct,
    "packageName" / int16_str_struct,
    "platform_str" / int16_str_struct,
    "ex_json_bus"/ int16_str_struct,
    "ex_json_vs" / int16_str_struct,
    "ck_guard_time" / int16_str_struct
)

# ============== 常量定义 ==============
DELTA = 0x9e3779b9
ROUNDS = 16
LOG_ROUNDS = 4
SALT_LEN = 2
ZERO_LEN = 7
TEA_CKEY = bytes.fromhex('59b2f7cf725ef43c34fdd7c123411ed3')
XOR_KEY = [0x84, 0x2E, 0xED, 0x08, 0xF0, 0x66, 0xE6, 0xEA, 0x48, 0xB4, 0xCA, 0xA9, 0x91, 0xED, 0x6F, 0xF3]
STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-='

class Size_t:
    def __init__(self, value):
        self.value = value

# ============== TEA加密算法 ==============
def TeaEncryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list(struct.unpack("!IIII", pKey))
    y, z = struct.unpack("!II", pInBuf[:8])
    
    sum_val = 0
    for _ in range(ROUNDS):
        sum_val += DELTA
        sum_val = ctypes.c_uint32(sum_val).value
        y += ((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        z += ((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value
    
    pOutBuf.clear()
    pOutBuf.extend(struct.pack("!II", y, z))

def TeaDecryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list(struct.unpack("!IIII", pKey))
    y, z = struct.unpack("!II", pInBuf[:8])
    
    sum_val = ctypes.c_uint32(DELTA << LOG_ROUNDS).value
    for _ in range(ROUNDS):
        z -= ((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value
        y -= ((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        sum_val -= DELTA
    
    pOutBuf.clear()
    pOutBuf.extend(struct.pack("!II", y, z))

def encrypt(key: bytes, sIn: bytes, iLength: int, buffer: bytearray) -> None:
    outlen = Size_t(oi_symmetry_encrypt2_len(iLength))
    oi_symmetry_encrypt2(sIn, iLength, key, buffer, outlen)
    while len(buffer) > outlen.value:
        buffer.pop()

def decrypt(key: bytes, sIn: bytes, iLength: int, buffer: bytearray) -> bool:
    outlen = Size_t(iLength)
    if not oi_symmetry_decrypt2(sIn, iLength, key, buffer, outlen):
        return False
    while len(buffer) > outlen.value:
        buffer.pop()
    return True

def oi_symmetry_encrypt2_len(nInBufLen: int) -> int:
    nPadSaltBodyZeroLen = nInBufLen + 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    return nPadSaltBodyZeroLen + nPadlen

def oi_symmetry_encrypt2(pInBuf: bytes, nInBufLen: int, pKey: bytes, pOutBuf: bytearray, pOutBufLen: Size_t) -> None:
    nPadSaltBodyZeroLen = nInBufLen + 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    
    src_buf = bytearray([0] * 8)
    src_buf[0] = (random.randint(0, 255) & 0xf8) | nPadlen
    src_i = 1
    
    while nPadlen:
        src_buf[src_i] = random.randint(0, 255)
        src_i += 1
        nPadlen -= 1
    
    iv_plain = bytearray([0] * 8)
    iv_crypt = bytearray(iv_plain)
    pOutBufLen.value = 0
    
    i = 1
    while i <= SALT_LEN:
        if src_i < 8:
            src_buf[src_i] = random.randint(0, 255)
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            
            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)
    
    pInBufIndex = 0
    while nInBufLen:
        if src_i < 8:
            src_buf[src_i] = pInBuf[pInBufIndex]
            pInBufIndex += 1
            src_i += 1
            nInBufLen -= 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            
            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)
    
    i = 1
    while i <= ZERO_LEN:
        if src_i < 8:
            src_buf[src_i] = 0
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            
            iv_plain = bytearray(src_buf)
            src_i = 0
            iv_crypt = temp_pOutBuf
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)

def oi_symmetry_decrypt2(pInBuf: bytes, nInBufLen: int, pKey: bytes, pOutBuf: bytearray, pOutBufLen: Size_t) -> bool:
    if (nInBufLen % 8) or (nInBufLen < 16):
        return False
    
    dest_buf = bytearray()
    TeaDecryptECB(pInBuf, pKey, dest_buf)
    
    nPadLen = dest_buf[0] & 0x7
    i = nInBufLen - 1 - nPadLen - SALT_LEN - ZERO_LEN
    
    if (pOutBufLen.value < i) or (i < 0):
        return False
    
    pOutBufLen.value = i
    zero_buf = bytearray([0] * 8)
    iv_pre_crypt = bytearray(zero_buf)
    iv_cur_crypt = bytearray(pInBuf)
    
    pInBuf = pInBuf[8:]
    nBufPos = 8
    dest_i = 1 + nPadLen
    
    i = 1
    while i <= SALT_LEN:
        if dest_i < 8:
            dest_i += 1
            i += 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf = pInBuf[8:]
            nBufPos += 8
            dest_i = 0
    
    nPlainLen = pOutBufLen.value
    while nPlainLen:
        if dest_i < 8:
            pOutBuf.append(dest_buf[dest_i] ^ iv_pre_crypt[dest_i])
            dest_i += 1
            nPlainLen -= 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf = pInBuf[8:]
            nBufPos += 8
            dest_i = 0
    
    i = 1
    while i <= ZERO_LEN:
        if dest_i < 8:
            if dest_buf[dest_i] ^ iv_pre_crypt[dest_i]:
                return False
            dest_i += 1
            i += 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf = pInBuf[8:]
            nBufPos += 8
            dest_i = 0
    
    return True

def tc_tea_encrypt(keys: bytes, message: bytes) -> bytes:
    data = bytearray()
    encrypt(keys, message, len(message), data)
    return bytes(data)

def tc_tea_decrypt(keys: bytes, message: bytes) -> bytes:
    data = bytearray()
    if decrypt(keys, message, len(message), data):
        return bytes(data)
    else:
        raise Exception('解密失败')

# ============== CKEY生成函数 ==============
def CalcSignature(decArray):
    signature = 0
    for byte in decArray:
        signature = (0x83 * signature + byte)
    return signature & 0x7FFFFFFF

def RandomHexStr(length):
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(length))

def XOR_Array(byteArray):
    retArray = bytearray(byteArray)
    for i in range(len(retArray)):
        retArray[i] ^= XOR_KEY[i & 0xF]
    return retArray

def custom_encode(text):
    encoded_data = base64.b64encode(text)
    encoded_str = encoded_data.decode('utf-8')
    translated_str = encoded_str.translate(str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET))
    return translated_str

def create_str_data(value):
    if value is None:
        value = ""
    if isinstance(value, int):
        value = str(value)
    return {"length": len(value), "value": value.encode('utf-8')}

def ckey42(Platform, Timestamp, Sdtfrom="fcgo", vid="600002264", guid=None, appVer="V8.22.1035.3031"):
    header = b'\x00\x00\x00\x42\x00\x00\x00\x04\x00\x00\x04\xd2'
    data = {
        "header": header,
        "Platform": int(Platform).to_bytes(4, 'big'),
        "signature": b'\x00\x00\x00\x00',
        "Timestamp": Timestamp.to_bytes(4, 'big'),
        "Sdtfrom": create_str_data(Sdtfrom),
        "randFlag": create_str_data(
            base64.b64encode(os.urandom(18)).decode()
        ),
        "appVer": create_str_data(appVer),
        "vid": create_str_data(vid),
        "guid": create_str_data(guid),
        "part1": 1,
        "isDlna": 1,
        "uid": create_str_data("2622783A"),
        "bundleID": create_str_data("nil"),
        "uuid4": create_str_data(str(uuid.uuid4())),
        "bundleID1": create_str_data("nil"),
        "ckeyVersion": create_str_data("v0.1.000"),
        "packageName": create_str_data("com.cctv.yangshipin.app.iphone"),
        "platform_str": create_str_data(str(Platform)),
        "ex_json_bus": create_str_data("ex_json_bus"),
        "ex_json_vs": create_str_data("ex_json_vs"),
        "ck_guard_time": create_str_data(RandomHexStr(66)),
    }
    Buffer = ckey_struct.build(data)
    BufferLenHex = hex(len(Buffer))[2:].zfill(4)
    BufferHead = [int(BufferLenHex[i:i+2], 16) for i in range(0, len(BufferLenHex), 2)]
    Buffer = BufferHead + list(Buffer)
    encrypt_data = tc_tea_encrypt(TEA_CKEY, bytes(Buffer))
    encrypt_data = bytearray(encrypt_data)
    CheckSum = CalcSignature(Buffer)
    CheckSumBytes = struct.pack('>I', CheckSum)
    encrypt_data.extend(CheckSumBytes)
    result = XOR_Array(encrypt_data)
    return "--01" + custom_encode(result).replace('=', '')

# ============== FastAPI应用 ==============
app = FastAPI()

def get_current_host(request: Request):
    """获取当前服务的主机地址"""
    host = request.headers.get('host')
    if host:
        return host
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return f"{local_ip}:10001"
    except:
        return "localhost:10001"

def generate_channel_list(host):
    """生成频道列表"""
    try:
        with open('ysp.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            # 替换端口号为当前服务地址
            content = content.replace(':8080/ysp?', f':{host.split(":")[-1] if ":" in host else "10001"}/ysp?')
            return content
    except:
        # 如果文件不存在，返回默认列表
        return "央视,#genre#\nCCTV1,http://localhost:10001/ysp?cnlid=2024078201&livepid=600001859&defn=fhd"

@app.get("/")
async def root(request: Request):
    """根路径，返回播放列表"""
    host = get_current_host(request)
    channel_list = generate_channel_list(host)
    return Response(content=channel_list, media_type="text/plain; charset=utf-8")

@app.get("/ysp")
def ysp(cnlid: str, livepid: str, defn: str = "auto"):
    """获取直播流"""
    try:
        url = "https://liveinfo.ysp.cctv.cn"
        params = {
            "atime": "120",
            "livepid": livepid,
            "cnlid": cnlid,
            "appVer": "V8.22.1035.3031",
            "app_version": "300090",
            "caplv": "1",
            "cmd": "2",
            "defn": defn,
            "device": "iPhone",
            "encryptVer": "4.2",
            "getpreviewinfo": "0",
            "hevclv": "33",
            "lang": "zh-Hans_JP",
            "livequeue": "0",
            "logintype": "1",
            "nettype": "1",
            "newnettype": "1",
            "newplatform": "4330403",
            "platform": "4330403",
            "playbacktime": "0",
            "sdtfrom": "v3021",
            "spacode": "23",
            "spaudio": "1",
            "spdemuxer": "6",
            "spdrm": "2",
            "spdynamicrange": "7",
            "spflv": "1",
            "spflvaudio": "1",
            "sphdrfps": "60",
            "sphttps": "0",
            "spvcode": "MSgzMDoyMTYwLDYwOjIxNjB8MzA6MjE2MCw2MDoyMTYwKTsyKDMwOjIxNjAsNjA6MjE2MHwzMDoyMTYwLDYwOjIxNjAp",
            "spvideo": "4",
            "stream": "1",
            "system": "1",
            "sysver": "ios18.2.1",
            "uhd_flag": "4",
        }
        headers = {
            'User-Agent': "qqlive",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }
        
        Platform = params['platform']
        Timestamp = int(time.time())
        appVer = params['appVer']
        Cnlid = params['cnlid']
        StaGuid = RandomHexStr(32)
        sdtfrom = 'dcgh'
        
        ckey = ckey42(Platform, Timestamp, sdtfrom, Cnlid, StaGuid, appVer)
        params.update({"cKey": ckey})
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        data = response.json()
        
        if defn == "auto":
            formats = data['formats']
            return JSONResponse(content={"formats": formats})
        
        url = data['playurl']
        return RedirectResponse(url=url)
        
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=10001)