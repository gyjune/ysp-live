# -*- coding: utf-8 -*-
import base64
import os
import random
import struct
import time
import uuid
import re
import json
import socket
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
import uvicorn

# ============== 频道映射 ==============
CHANNELS = {
    'cctv1': ['2024078201', '600001859', 'fhd'],  # CCTV-1高清
    'cctv2': ['2024075401', '600001800', 'fhd'],  # CCTV-2高清
    'cctv3': ['2024068501', '600001801', 'fhd'],  # CCTV-3高清
    'cctv4': ['2029797101', '600001814', 'fhd'],  # CCTV-4高清
    'cctv5': ['2024078401', '600001818', 'fhd'],  # CCTV-5高清
    'cctv5p': ['2024078001', '600001817', 'fhd'],  # CCTV-5+高清
    'cctv6': ['2013693901', '600108442', 'fhd'],  # CCTV-6高清
    'cctv7': ['2024072001', '600004092', 'fhd'],  # CCTV-7高清
    'cctv8': ['2029793001', '600001803', 'fhd'],  # CCTV-8高清
    'cctv9': ['2024078601', '600004078', 'fhd'],  # CCTV-9高清
    'cctv10': ['2024078701', '600001805', 'fhd'],  # CCTV-10高清
    'cctv11': ['2027248701', '600001806', 'fhd'],  # CCTV-11高清
    'cctv12': ['2027248801', '600001807', 'fhd'],  # CCTV-12高清
    'cctv13': ['2029797201', '600001811', 'fhd'],  # CCTV-13高清
    'cctv14': ['2027248901', '600001809', 'fhd'],  # CCTV-14高清
    'cctv15': ['2027249001', '600001815', 'fhd'],  # CCTV-15高清
    'cctv16': ['2027249101', '600098637', 'fhd'],  # CCTV-16高清
    'cctv164k': ['2027249301', '600099502', 'fhd'],  # CCTV-16(4K)
    'cctv17': ['2027249401', '600001810', 'fhd'],  # CCTV-17高清
    'cctv4k': ['2029810301', '600002264', 'fhd'],  # CCTV-4K
    'cctv8k': ['2026774101', '600156816', 'fhd'],  # CCTV-8K
    'cgtn': ['2024181701', '600014550', 'fhd'],  # CGTN
    'cgtnfy': ['2024181801', '600084704', 'fhd'],  # CGTN法语频道
    'cgtney': ['2024181901', '600084758', 'fhd'],  # CGTN俄语频道
    'cgtnalby': ['2024182001', '600084782', 'fhd'],  # CGTN阿拉伯语频道
    'cgtnxby': ['2024182101', '600084744', 'fhd'],  # CGTN西班牙语频道
    'cgtnwyjl': ['2024182301', '600084781', 'fhd'],  # CGTN外语纪录频道
    'cctvfyjc': ['2025637103', '600099658', 'shd'],  # CCTV风云剧场频道
    'cctvdyjc': ['2026874203', '600099655', 'shd'],  # CCTV第一剧场频道
    'cctvhjjc': ['2026874303', '600099620', 'shd'],  # CCTV怀旧剧场频道
    'cctvsjdl': ['2026874403', '600099637', 'shd'],  # CCTV世界地理频道
    'cctvfyyy': ['2026874503', '600099660', 'shd'],  # CCTV风云音乐频道
    'cctvbqkj': ['2026874603', '600099649', 'shd'],  # CCTV兵器科技频道
    'cctvfyzq': ['2026966203', '600099636', 'shd'],  # CCTV风云足球频道
    'cctvgeqwq': ['2026874703', '600099659', 'shd'],  # CCTV高尔夫·网球频道
    'cctvnxss': ['2026874803', '600099650', 'shd'],  # CCTV女性时尚频道
    'cctvyswhjp': ['2026874903', '600099653', 'shd'],  # CCTV央视文化精品频道
    'cctvystq': ['2026875003', '600099652', 'shd'],  # CCTV央视台球频道
    'cctvdszn': ['2026875103', '600099656', 'shd'],  # CCTV电视指南频道
    'cctvwsjk': ['2025637003', '600099651', 'shd'],  # CCTV卫生健康频道
    'bjws': ['2024052703', '600002309', 'fhd'],  # 北京卫视
    'jsws': ['2024171103', '600002521', 'fhd'],  # 江苏卫视
    'dfws': ['2024054503', '600002483', 'fhd'],  # 东方卫视
    'zjws': ['2024054703', '600002520', 'fhd'],  # 浙江卫视
    'hnws': ['2024054803', '600002475', 'fhd'],  # 湖南卫视
    'hbws': ['2024171203', '600002508', 'fhd'],  # 湖北卫视
    'gdws': ['2024060903', '600002485', 'fhd'],  # 广东卫视
    'gxws': ['2024060703', '600002509', 'fhd'],  # 广西卫视
    'hljws': ['2029797003', '600002498', 'fhd'],  # 黑龙江卫视
    'hnws2': ['2024055603', '600002506', 'fhd'],  # 海南卫视
    'cqws': ['2024061103', '600002531', 'fhd'],  # 重庆卫视
    'szws': ['2024061303', '600002481', 'fhd'],  # 深圳卫视
    'scws': ['2024061403', '600002516', 'fhd'],  # 四川卫视
    'henanws': ['2029797303', '600002525', 'fhd'],  # 河南卫视
    'fjdnhz': ['2024061503', '600002484', 'fhd'],  # 福建东南卫视
    'gzhws': ['2024061603', '600002490', 'fhd'],  # 贵州卫视
    'jxws': ['2024061703', '600002503', 'fhd'],  # 江西卫视
    'lnws': ['2024171303', '600002505', 'fhd'],  # 辽宁卫视
    'ahws': ['2024171403', '600002532', 'fhd'],  # 安徽卫视
    'hbws2': ['2024171503', '600002493', 'fhd'],  # 河北卫视
    'sdws': ['2029787903', '600002513', 'fhd'],  # 山东卫视
    'tjws': ['2019927003', '600152137', 'fhd'],  # 天津卫视
    'jlws': ['2025561503', '600190405', 'fhd'],  # 吉林卫视
    'shanxiws': ['2029795103', '600190400', 'fhd'],  # 陕西卫视
    'nxws': ['2025608503', '600190737', 'fhd'],  # 宁夏卫视
    'nmgws': ['2025561203', '600190401', 'fhd'],  # 内蒙古卫视
    'ynws': ['2025561303', '600190402', 'fhd'],  # 云南卫视
    'shanxiws2': ['2025560803', '600190407', 'fhd'],  # 山西卫视
    'qhws': ['2025559103', '600190406', 'fhd'],  # 青海卫视
    'xzws': ['2025558003', '600190403', 'fhd'],  # 西藏卫视
    'cetv1': ['2022823801', '600171827', 'fhd'],  # 中国教育电视台1频道
    'gxpd': ['2029360403', '600213139', 'fhd'],  # 国学频道
    'xjws': ['2019927403', '600152138', 'fhd']  # 新疆卫视
}

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
def TeaEncryptECB(pInBuf, pKey, pOutBuf):
    k = list(struct.unpack(">IIII", pKey))
    y, z = struct.unpack(">II", pInBuf[:8])

    sum_val = 0
    for _ in range(ROUNDS):
        sum_val = (sum_val + DELTA) & 0xFFFFFFFF
        y = (y + (((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1]))) & 0xFFFFFFFF
        z = (z + (((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3]))) & 0xFFFFFFFF

    pOutBuf.clear()
    pOutBuf.extend(struct.pack(">II", y, z))


def TeaDecryptECB(pInBuf, pKey, pOutBuf):
    k = list(struct.unpack(">IIII", pKey))
    y, z = struct.unpack(">II", pInBuf[:8])

    sum_val = (DELTA << LOG_ROUNDS) & 0xFFFFFFFF

    for _ in range(ROUNDS):
        z = (z - (((y << 4) + k[2]) ^ (y + sum_val) ^ ((y >> 5) + k[3]))) & 0xFFFFFFFF
        y = (y - (((z << 4) + k[0]) ^ (z + sum_val) ^ ((z >> 5) + k[1]))) & 0xFFFFFFFF
        sum_val = (sum_val - DELTA) & 0xFFFFFFFF

    pOutBuf.clear()
    pOutBuf.extend(struct.pack(">II", y, z))


def oi_symmetry_encrypt2_len(nInBufLen):
    nPadSaltBodyZeroLen = nInBufLen + 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    return nPadSaltBodyZeroLen + nPadlen


def oi_symmetry_encrypt2(pInBuf, nInBufLen, pKey, pOutBuf, pOutBufLen):
    nPadSaltBodyZeroLen = nInBufLen + 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen

    src_buf = bytearray([0] * 8)
    src_buf[0] = (random.randint(0, 255) & 0xF8) | nPadlen
    src_i = 1

    while nPadlen:
        src_buf[src_i] = random.randint(0, 255)
        src_i += 1
        nPadlen -= 1

    iv_plain = bytearray([0] * 8)
    iv_crypt = bytearray(iv_plain)
    pOutBufLen.value = 0

    i = 0
    while i < SALT_LEN:
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

    i = 0
    while i < ZERO_LEN:
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
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf.extend(temp_pOutBuf)

    if src_i > 0:
        for j in range(src_i, 8):
            src_buf[j] = 0

        for j in range(8):
            src_buf[j] ^= iv_crypt[j]

        temp_pOutBuf = bytearray()
        TeaEncryptECB(src_buf, pKey, temp_pOutBuf)

        for j in range(8):
            temp_pOutBuf[j] ^= iv_plain[j]

        pOutBufLen.value += 8
        pOutBuf.extend(temp_pOutBuf)


def encrypt(key, sIn, iLength, buffer):
    outlen = Size_t(oi_symmetry_encrypt2_len(iLength))
    oi_symmetry_encrypt2(sIn, iLength, key, buffer, outlen)
    while len(buffer) > outlen.value:
        buffer.pop()


# ============== 辅助函数 ==============
def calc_signature(dec_array):
    signature = 0
    for byte in dec_array:
        signature = (0x83 * signature + byte) & 0x7FFFFFFF
    return signature


def random_hex_str(length):
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(length))


def xor_array(byte_array):
    ret_array = bytearray(byte_array)
    for i in range(len(ret_array)):
        ret_array[i] ^= XOR_KEY[i & 0xF]
    return ret_array


def custom_encode(text):
    encoded = base64.b64encode(text).decode('utf-8')
    return encoded.translate(str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET))


def pack_string(s):
    if isinstance(s, str):
        s = s.encode('utf-8')
    return struct.pack('>H', len(s)) + s


def build_packet(params):
    data = bytearray()

    # 1. 头部 (12字节)
    data.extend(b'\x00\x00\x00\x42\x00\x00\x00\x04\x00\x00\x04\xd2')

    # 2. Platform (4字节)
    data.extend(struct.pack('>I', params['Platform']))

    # 3. Signature (4字节) - 先置0
    data.extend(struct.pack('>I', 0))

    # 4. Timestamp (4字节)
    data.extend(struct.pack('>I', params['Timestamp']))

    # 5. Sdtfrom
    data.extend(pack_string(params['Sdtfrom']))

    # 6. randFlag
    data.extend(pack_string(params['randFlag']))

    # 7. appVer
    data.extend(pack_string(params['appVer']))

    # 8. vid
    data.extend(pack_string(params['vid']))

    # 9. guid
    data.extend(pack_string(params['guid']))

    # 10. part1 (4字节)
    data.extend(struct.pack('>I', 1))

    # 11. isDlna (4字节)
    data.extend(struct.pack('>I', 1))

    # 12. uid
    data.extend(pack_string("2622783A"))

    # 13. bundleID
    data.extend(pack_string("nil"))

    # 14. uuid4
    data.extend(pack_string(params['uuid4']))

    # 15. bundleID1
    data.extend(pack_string("nil"))

    # 16. ckeyVersion
    data.extend(pack_string("v0.1.000"))

    # 17. packageName
    data.extend(pack_string("com.cctv.yangshipin.app.iphone"))

    # 18. platform_str
    data.extend(pack_string(str(params['Platform'])))

    # 19. ex_json_bus
    data.extend(pack_string("ex_json_bus"))

    # 20. ex_json_vs
    data.extend(pack_string("ex_json_vs"))

    # 21. ck_guard_time
    data.extend(pack_string(params['ck_guard_time']))

    # 添加长度头
    body_length = len(data)
    buffer = struct.pack('>H', body_length) + data

    # 计算签名
    signature = calc_signature(list(buffer))

    # 更新签名 (位置: 2 + 12 + 4 = 18)
    buffer = bytearray(buffer)
    struct.pack_into('>I', buffer, 18, signature)

    return bytes(buffer)


def encrypt_data_to_ckey(data):
    tea_ckey = TEA_CKEY

    checksum = calc_signature(list(data))

    encrypted = bytearray()
    outlen = Size_t(oi_symmetry_encrypt2_len(len(data)))
    oi_symmetry_encrypt2(data, len(data), tea_ckey, encrypted, outlen)
    encrypted += struct.pack('>I', checksum)

    result = xor_array(encrypted)
    return "--01" + custom_encode(result)


def generate_ckey(cnlid, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())

    guid = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    rand_flag = '_zj1A5Gh6QYcxWjIUGos2w=='
    uuid4 = str(uuid.uuid4())
    ck_guard_time = random_hex_str(66)

    params = {
        'Platform': 4330403,
        'Timestamp': timestamp,
        'Sdtfrom': 'dcgh',
        'vid': cnlid,
        'guid': guid,
        'appVer': 'V8.22.1035.3031',
        'randFlag': rand_flag,
        'uuid4': uuid4,
        'ck_guard_time': ck_guard_time
    }

    buffer = build_packet(params)
    ckey = encrypt_data_to_ckey(buffer)

    return {
        'ckey': ckey,
        'params': params,
        'buffer': buffer
    }


def spvcode(defn):
    return "MSgzMDoyMTYwLDYwOjIxNjB8MzA6MjE2MCw2MDoyMTYwKTsyKDMwOjIxNjAsNjA6MjE2MHwzMDoyMTYwLDYwOjIxNjAp"


def send_http_request(params):
    url = "https://bkliveinfo.ysp.cctv.cn"

    try:
        response = requests.get(url, params=params, timeout=15,
                                headers={
                                    'User-Agent': 'qqlive',
                                    'Connection': 'Keep-Alive',
                                    'Accept': 'application/json'
                                })
        data = response.json()

        if 'iretcode' in data:
            result = {
                'success': data['iretcode'] == 0,
                'iretcode': data['iretcode'],
                'http_code': response.status_code,
                'response': data
            }

            if data['iretcode'] == 0:
                result['playurl'] = data.get('playurl')
            else:
                result['error'] = data.get('errinfo', '未知错误')

            return result

        return {
            'success': False,
            'error': '无效的JSON响应',
            'http_code': response.status_code,
            'raw_response': response.text[:500]
        }

    except Exception as e:
        return {
            'success': False,
            'error': f'请求错误: {str(e)}'
        }


def get_play_url(cnlid, livepid, defn, playseek=None):
    timestamp = int(time.time())
    ckey_result = generate_ckey(cnlid, timestamp)

    flowid = f"{uuid.uuid4()}_4330403"

    is_playback = playseek is not None and playseek != ''
    playback_timestamp = None

    if is_playback:
        try:
            parts = playseek.split('-')
            start_time_str = parts[0]
            dt = datetime.strptime(start_time_str, '%Y%m%d%H%M%S')
            dt = dt.replace(tzinfo=timezone(timedelta(hours=8)))
            playback_timestamp = int(dt.timestamp())
        except Exception as e:
            return None

    spvcode_val = spvcode(defn)
    request_params = {
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
        "spvcode": spvcode_val,
        "spvideo": "4",
        "stream": "1",
        "system": "1",
        "sysver": "ios18.2.1",
        "uhd_flag": "4",
        "cKey": ckey_result['ckey'],
        "guid": ckey_result['params']['guid'],
        "fntick": str(timestamp),
        "flowid": flowid,
    }

    if is_playback:
        request_params['playbacktime'] = playback_timestamp
        response = send_http_request(request_params)

        if response['success'] and 'playurl' in response:
            return response['playurl']
        else:
            del request_params['playbacktime']
            response = send_http_request(request_params)

            if response['success'] and 'playurl' in response:
                playurl = response['playurl']
                # 修改域名添加starttime
                parts = playurl.split('/')
                if len(parts) >= 3:
                    parts[2] = 'tlivecloud-playback-cdn.ysp.cctv.cn/tcloud.cctv.com'
                    playurl = '/'.join(parts)
                    if '?' in playurl:
                        playurl += f'&starttime={playback_timestamp}'
                    else:
                        playurl += f'?starttime={playback_timestamp}'
                return playurl
            else:
                return None
    else:
        request_params['playbacktime'] = "0"
        response = send_http_request(request_params)
        if response['success'] and 'playurl' in response:
            return response['playurl']
        return None


# ============== FastAPI应用 ==============
app = FastAPI(title="央视影音直播代理", description="央视影音 PHP 转 Python FastAPI 版本")

# 频道名称映射
CHANNEL_NAMES = {
    'cctv1': 'CCTV1', 'cctv2': 'CCTV2', 'cctv3': 'CCTV3', 'cctv4': 'CCTV4',
    'cctv5': 'CCTV5', 'cctv5p': 'CCTV5+', 'cctv6': 'CCTV6', 'cctv7': 'CCTV7',
    'cctv8': 'CCTV8', 'cctv9': 'CCTV9', 'cctv10': 'CCTV10', 'cctv11': 'CCTV11',
    'cctv12': 'CCTV12', 'cctv13': 'CCTV13', 'cctv14': 'CCTV14', 'cctv15': 'CCTV15',
    'cctv16': 'CCTV16', 'cctv164k': 'CCTV16(4K)', 'cctv17': 'CCTV17',
    'cctv4k': 'CCTV4K', 'cctv8k': 'CCTV8K',
    'cgtn': 'CGTN', 'cgtnfy': 'CGTN法语', 'cgtney': 'CGTN俄语',
    'cgtnalby': 'CGTN阿拉伯语', 'cgtnxby': 'CGTN西班牙语', 'cgtnwyjl': 'CGTN外语纪录',
    'cctvfyjc': 'CCTV风云剧场', 'cctvdyjc': 'CCTV第一剧场', 'cctvhjjc': 'CCTV怀旧剧场',
    'cctvsjdl': 'CCTV世界地理', 'cctvfyyy': 'CCTV风云音乐', 'cctvbqkj': 'CCTV兵器科技',
    'cctvfyzq': 'CCTV风云足球', 'cctvgeqwq': 'CCTV高尔夫·网球', 'cctvnxss': 'CCTV女性时尚',
    'cctvyswhjp': 'CCTV央视文化精品', 'cctvystq': 'CCTV央视台球', 'cctvdszn': 'CCTV电视指南',
    'cctvwsjk': 'CCTV卫生健康',
    'bjws': '北京卫视', 'jsws': '江苏卫视', 'dfws': '东方卫视', 'zjws': '浙江卫视',
    'hnws': '湖南卫视', 'hbws': '湖北卫视', 'gdws': '广东卫视', 'gxws': '广西卫视',
    'hljws': '黑龙江卫视', 'hnws2': '海南卫视', 'cqws': '重庆卫视', 'szws': '深圳卫视',
    'scws': '四川卫视', 'henanws': '河南卫视', 'fjdnhz': '福建东南卫视', 'gzhws': '贵州卫视',
    'jxws': '江西卫视', 'lnws': '辽宁卫视', 'ahws': '安徽卫视', 'hbws2': '河北卫视',
    'sdws': '山东卫视', 'tjws': '天津卫视', 'jlws': '吉林卫视', 'shanxiws': '陕西卫视',
    'nxws': '宁夏卫视', 'nmgws': '内蒙古卫视', 'ynws': '云南卫视', 'shanxiws2': '山西卫视',
    'qhws': '青海卫视', 'xzws': '西藏卫视', 'cetv1': '中国教育电视台1', 'gxpd': '国学频道',
    'xjws': '新疆卫视'
}


def get_server_host(request: Request):
    """获取服务器地址"""
    host = request.headers.get('host')
    if host:
        return host
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
        return f"{server_ip}:10001"
    except:
        return "localhost:10001"


@app.get("/")
async def root(request: Request):
    """根路径 - 返回M3U格式频道列表"""
    host = get_server_host(request)
    lines = ["央视,#genre#"]

    for key in CHANNELS:
        name = CHANNEL_NAMES.get(key, key)
        lines.append(f"{name},http://{host}/ysp?id={key}")

    return Response(content="\n".join(lines), media_type="text/plain; charset=utf-8")


@app.get("/ysp")
async def get_stream(id: str, playseek: Optional[str] = None):
    """
    获取直播流
    - id: 频道ID (如 cctv1, bjws 等)
    - playseek: 回看时间 (格式: YYYYMMDDHHMMSS-YYYYMMDDHHMMSS)
    """
    if id not in CHANNELS:
        return JSONResponse(
            content={"error": f"频道 '{id}' 不存在", "available": list(CHANNELS.keys())},
            status_code=404
        )

    cnlid, livepid, defn = CHANNELS[id]

    # 获取播放地址
    play_url = get_play_url(cnlid, livepid, defn, playseek)

    if play_url:
        return RedirectResponse(url=play_url)
    else:
        return JSONResponse(
            content={"error": "获取播放地址失败，请稍后重试"},
            status_code=500
        )


@app.get("/channels")
async def list_channels():
    """列出所有可用频道"""
    return JSONResponse(content={
        "channels": [
            {"id": key, "name": CHANNEL_NAMES.get(key, key)}
            for key in CHANNELS
        ]
    })


@app.get("/info/{id}")
async def channel_info(id: str):
    """获取频道详细信息"""
    if id not in CHANNELS:
        return JSONResponse(content={"error": "频道不存在"}, status_code=404)

    cnlid, livepid, defn = CHANNELS[id]
    return JSONResponse(content={
        "id": id,
        "name": CHANNEL_NAMES.get(id, id),
        "cnlid": cnlid,
        "livepid": livepid,
        "defn": defn
    })


@app.get("/test/{id}")
async def test_channel(id: str):
    """测试频道 - 返回cKey生成和请求详情"""
    if id not in CHANNELS:
        return JSONResponse(content={"error": "频道不存在"}, status_code=404)

    cnlid, livepid, defn = CHANNELS[id]

    # 生成cKey
    timestamp = int(time.time())
    ckey_result = generate_ckey(cnlid, timestamp)

    # 构建请求参数
    request_params = {
        "cnlid": cnlid,
        "livepid": livepid,
        "defn": defn,
        "cKey": ckey_result['ckey'][:50] + "...",
        "guid": ckey_result['params']['guid'],
        "timestamp": timestamp,
        "ck_guard_time": ckey_result['params']['ck_guard_time']
    }

    return JSONResponse(content={
        "channel": id,
        "name": CHANNEL_NAMES.get(id, id),
        "params": request_params,
        "ckey_full": ckey_result['ckey']
    })


# ============== 启动服务 ==============
if __name__ == '__main__':
    print("=" * 60)
    print("央视影音直播代理服务启动")
    print("=" * 60)
    print(f"服务地址: http://0.0.0.0:10001")
    print(f"频道列表: http://0.0.0.0:10001/")
    print(f"播放示例: http://0.0.0.0:10001/ysp?id=cctv1")
    print(f"频道列表JSON: http://0.0.0.0:10001/channels")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=10001)