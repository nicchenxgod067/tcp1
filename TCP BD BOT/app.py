import ssl
import asyncio
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import GetLoginDataRes_pb2
import DecodeWhisperMsg_pb2
import GenWhisperMsg_pb2
from datetime import datetime
import bot_mode_pb2
import bot_invite_pb2
import base64
import json
import jwt
from flask import Flask, request, jsonify, render_template_string
from threading import Thread
import time
import Clan_Startup_pb2
import clan_msg_pb2
import requests
from protobuf_utils import (
    create_uid_generator, parse_like_info, 
    encode_uid, encrypt_api, encrypt_message,
    AES, pad, binascii
)
import threading

# Flask app setup
app = Flask(__name__)

# Shared dictionaries for bot tokens, tasks, and online writers
bot_tasks = {}
bot_tokens = {}
bot_online_writers = {}  # Global dictionary to store online writers
bot_tokens_lock = threading.Lock()
bot_last_seen = {}  # Track last activity time for each bot

# API Endpoints for BD region
BD_API_BASE = "https://clientbp.ggblueshark.com"
API_ENDPOINTS = {
    'ADD_FRIEND': f"{BD_API_BASE}/RequestAddingFriend",
    'REMOVE_FRIEND': f"{BD_API_BASE}/RemoveFriend"
}

# Common Headers for BD API requests
DEFAULT_HEADERS = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB50',
    'Host': 'clientbp.ggblueshark.com'
}

# Token expiry configuration (10 minutes)
TOKEN_EXPIRY_SECONDS = 10 * 60

# Headers for bot API requests
headers = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50"
}

# Utility functions
def _get_headers(token):
    headers = DEFAULT_HEADERS.copy()
    headers['Authorization'] = f'Bearer {token}'
    return headers

async def encrypted_proto(data):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(data, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

async def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status != 200:
                return (None, None)
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def MajorLoginProto_Encode(open_id, access_token):
    major_login = MajorLoginReq_pb2.MajorLogin()
    major_login.event_time = "2025-06-04 19:48:07"
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.114.6"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019117863"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    headers['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()

async def MajorLogin_Decode(MajorLoginResponse):
    proto = MajorLoginRes_pb2.MajorLoginRes()
    proto.ParseFromString(MajorLoginResponse)
    return proto

async def GetLoginData_Decode(GetLoginDataResponse):
    proto = GetLoginDataRes_pb2.GetLoginData()
    proto.ParseFromString(GetLoginDataResponse)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DecodeWhisperMsg_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto

async def base_to_hex(timestamp):
    timestamp_result = hex(timestamp)
    result = str(timestamp_result)[2:]
    if len(result) == 1:
        result = "0" + result
    return result

async def split_text_by_words(text, max_length=200):
    def insert_c_in_number(word):
        if word.isdigit():
            mid = len(word) // 2
            return word[:mid] + "[C]" + word[mid:]
        return word
    words = text.split()
    words = [insert_c_in_number(word) for word in words]
    chunks = []
    current = ""
    for word in words:
        if len(current) + len(word) + (1 if current else 0) <= max_length:
            current += (" " if current else "") + word
        else:
            chunks.append(current)
            current = word
    if current:
        chunks.append(current)
    return chunks

async def encrypt_packet(packet, key, iv):
    bytes_packet = bytes.fromhex(packet)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(bytes_packet, AES.block_size))
    return cipher_text.hex()

async def create_clan_startup(clan_id, clan_compiled_data, key, iv, writer):
    proto = Clan_Startup_pb2.ClanPacket()
    proto.Clan_Pos = 3
    proto.Data.Clan_ID = int(clan_id)
    proto.Data.Clan_Type = 1
    proto.Data.Clan_Compiled_Data = clan_compiled_data
    packet = proto.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "1201000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "120100000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "12010000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "1201000" + packet_length_hex + encrypted_packet
    writer.write(bytes.fromhex(final_packet))
    await writer.drain()

async def create_group(bot_name, key, iv):
    packet = "0801128a0612021d01180f20032a02656e420c0a044944433110121a024244420c0a044944433210561a024244480152090104090a121619201d580168017291050a8001303846464233424444463139454538463032303532463032323232323030303030303941303030323030393830303346364334303135434430414244433243303431373232393134313130313034306565363236653532636236636163626536363832346263323230303030303034383064306630383063363936386339633810b7031ad6037e51595c1002034e05530a0b0c0458520055565551550b0b530002045550540352590e0d080202561100014f7d55454d4a1b031e001910090a49124163795e5640777956534066704319585f4b0d5a424a695f62630c1302447f565c077b075c797b54570c516a607c72610878775000065b7a030e11094c5c40600c76450a71006461585e50027c5a435a584b417b426d5e4a0e10064e496a50736e775d065e7061065275577a015f0a7d72465f5b01615b081a02004f57075f794e75444c717a76640954577b13410b547454717f7b064b05160b4f4606586b635b4e515f12475c4a0461007e516d594c5a4a78455e470e1b01490d0602401d704644740a7a0c46645456036303496a654c754665060c130200446f00605d4354607a516813775f447f477066080b00504f6958655c0f12034f5079564049070a6b03486b134b7a4a777c0463795b65480c7772540e10064d08490869674075516b55017d580013066a057b66655e5d00095a5a041001034e73077a0c085e6c715e47400565444f74447c690a6a7406487a6857081a505c5d5458571c4d5f5616415640515e5e55515f1a4c54505c4245595c5659594b5640505d5f565a5f4442525a1c0460595c767d53595e447c046472597e6b4d5b48046a720f22047d5c5d57300c3a1a170240414202000a0b041d17677b7b63746c7451577a5b5650594208312e3131312e3130480650019801c402aa01024f52c201050803108703c20105080410de02c20105080510c001c20105081d109501c2010408161073c20105080e10af01c201020815"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0519000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051900000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    bot_online_writers[bot_name].write(bytes.fromhex(final_packet))
    await bot_online_writers[bot_name].drain()

async def modify_team_player(bot_name, team, key, iv):
    bot_mode = bot_mode_pb2.BotMode()
    bot_mode.key1 = 17
    bot_mode.key2.uid = 7802788212
    bot_mode.key2.key2 = 1
    bot_mode.key2.key3 = int(team)
    bot_mode.key2.key4 = 62
    bot_mode.key2.byte = base64.b64decode("Gg==")
    bot_mode.key2.key8 = 5
    bot_mode.key2.key13 = 227
    packet = bot_mode.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0519000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051900000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    bot_online_writers[bot_name].write(bytes.fromhex(final_packet))
    await bot_online_writers[bot_name].drain()

async def invite_target(bot_name, uid, region, key, iv):
    invite = bot_invite_pb2.invite_uid()
    invite.num = 2
    invite.Func.uid = int(uid)
    invite.Func.region = region
    invite.Func.number = 1
    packet = invite.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0519000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051900000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    bot_online_writers[bot_name].write(bytes.fromhex(final_packet))
    await bot_online_writers[bot_name].drain()

async def left_group(bot_name, key, iv):
    packet = "0807120608da89d98d27"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0519000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051900000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    bot_online_writers[bot_name].write(bytes.fromhex(final_packet))
    await bot_online_writers[bot_name].drain()

async def send_clan_msg(msg, chat_id, key, iv):
    try:
        # Ensure key and iv are bytes with correct length
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
            
        # Pad key to valid AES key length (16, 24, or 32 bytes)
        key_length = len(key)
        if key_length < 16:
            key = key.ljust(16, b'\0')[:16]
        elif 16 < key_length < 24:
            key = key.ljust(24, b'\0')[:24]
        elif 24 < key_length < 32:
            key = key.ljust(32, b'\0')[:32]
        
        # Ensure IV is exactly 16 bytes
        if len(iv) < 16:
            iv = iv.ljust(16, b'\0')[:16]
        else:
            iv = iv[:16]
            
        root = clan_msg_pb2.clan_msg()
        root.type = 1
        nested_object = root.data
        nested_object.uid = 7802788212
        nested_object.chat_id = chat_id
        nested_object.chat_type = 1
        nested_object.msg = msg
        nested_object.timestamp = int(datetime.now().timestamp())
        nested_details = nested_object.field9
        nested_details.Nickname = "TDS_FF_BOT"
        nested_details.avatar_id = 902000306
        nested_details.banner_id = 901041021
        nested_details.rank = 330
        nested_details.Clan_Name = "PGㅤEMP1RE"
        nested_details.field10 = 1
        nested_details.rank_point = 1
        nested_object.language = "en"
        nested_object.empty_field.SetInParent()
        nested_options = nested_object.field13
        nested_options.url = "https://graph.facebook.com/v9.0/147045590125499/picture?width=160&height=160"
        nested_options.url_type = 1
        nested_options.url_platform = 1
        
        packet = root.SerializeToString().hex()
        encrypted_packet = await encrypt_packet(packet, key, iv)
        packet_length = len(encrypted_packet) // 2
        hex_length = await base_to_hex(packet_length)
        
        if len(hex_length) == 2:
            final_packet = "1215000000" + hex_length + encrypted_packet
        elif len(hex_length) == 3:
            final_packet = "121500000" + hex_length + encrypted_packet
        elif len(hex_length) == 4:
            final_packet = "12150000" + hex_length + encrypted_packet
        elif len(hex_length) == 5:
            final_packet = "1215000" + hex_length + encrypted_packet
            
        return bytes.fromhex(final_packet)
    except Exception as e:
        print(f"Error in send_clan_msg: {e}")
        import traceback
        traceback.print_exc()
        return None

async def send_msg(msg, chat_id, key, iv):
    try:
        # Ensure key and iv are bytes with correct length
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
            
        # Pad key to valid AES key length (16, 24, or 32 bytes)
        key_length = len(key)
        if key_length < 16:
            key = key.ljust(16, b'\0')[:16]
        elif 16 < key_length < 24:
            key = key.ljust(24, b'\0')[:24]
        elif 24 < key_length < 32:
            key = key.ljust(32, b'\0')[:32]
        
        # Ensure IV is exactly 16 bytes
        if len(iv) < 16:
            iv = iv.ljust(16, b'\0')[:16]
        else:
            iv = iv[:16]
            
        root = GenWhisperMsg_pb2.GenWhisper()
        root.type = 1
        nested_object = root.data
        nested_object.uid = 7802788212
        nested_object.chat_id = chat_id
        nested_object.chat_type = 2
        nested_object.msg = msg
        nested_object.timestamp = int(datetime.now().timestamp())
        nested_details = nested_object.field9
        nested_details.Nickname = "TDS_FF_BOT"
        nested_details.avatar_id = 902000306
        nested_details.banner_id = 901041021
        nested_details.rank = 330
        nested_details.Clan_Name = "PGㅤEMP1RE"
        nested_details.field10 = 1
        nested_details.global_rank_pos = 1
        nested_object.language = "en"
        nested_options = nested_object.field13
        nested_options.url = "https://graph.facebook.com/v9.0/147045590125499/picture?width=160&height=160"
        nested_options.url_type = 2
        nested_options.url_platform = 1
        root.data.Celebrity = 1919408565318037500
        root.data.empty_field.SetInParent()
        
        packet = root.SerializeToString().hex()
        encrypted_packet = await encrypt_packet(packet, key, iv)
        packet_length = len(encrypted_packet) // 2
        hex_length = await base_to_hex(packet_length)
        
        if len(hex_length) == 2:
            final_packet = "1215000000" + hex_length + encrypted_packet
        elif len(hex_length) == 3:
            final_packet = "121500000" + hex_length + encrypted_packet
        elif len(hex_length) == 4:
            final_packet = "12150000" + hex_length + encrypted_packet
        elif len(hex_length) == 5:
            final_packet = "1215000" + hex_length + encrypted_packet
            
        return bytes.fromhex(final_packet)
    except Exception as e:
        print(f"Error in send_msg: {e}")
        import traceback
        traceback.print_exc()
        return None

async def get_encrypted_startup(AccountUID, token, timestamp, key, iv):
    uid_hex = hex(AccountUID)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await base_to_hex(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await encrypt_packet(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9:
        headers = '0000000'
    elif uid_length == 8:
        headers = '00000000'
    elif uid_length == 10:
        headers = '000000'
    elif uid_length == 7:
        headers = '000000000'
    packet = f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
    return packet

async def handle_tcp_online_connection(ip, port, encrypted_startup, bot_name, reconnect_delay=1):
    current_task = asyncio.current_task()
    while True:
        try:
            print("\n🔵 Connecting to online server...")
            reader, writer = await asyncio.open_connection(ip, int(port))
            bytes_payload = bytes.fromhex(encrypted_startup)
            writer.write(bytes_payload)
            await writer.drain()
            print("🟢 Account is now ONLINE")
            bot_online_writers[bot_name] = writer
            while True:
                data = await reader.read(9999)
                if not data:
                    print("\n🔴 Connection to online server lost")
                    break
                with bot_tokens_lock:
                    for name, task in bot_tasks.items():
                        if task == current_task:
                            bot_last_seen[name] = time.time()
                            break
            writer.close()
            await writer.wait_closed()
        except asyncio.CancelledError:
            print(f"TCP online connection for {bot_name} cancelled")
            break
        except Exception as e:
            print(f"\n🔴 Connection error: {str(e)}")
            print("🔄 Reconnecting in 5 seconds...")
        await asyncio.sleep(reconnect_delay)

async def handle_tcp_connection(ip, port, encrypted_startup, key, iv, Decode_GetLoginData, ready_event, bot_region, bot_name, reconnect_delay=1):
    current_task = asyncio.current_task()
    while True:
        try:
            print("\n🔵 Establishing game connection...")
            reader, writer = await asyncio.open_connection(ip, int(port))
            bytes_payload = bytes.fromhex(encrypted_startup)
            writer.write(bytes_payload)
            await writer.drain()
            print("🟢 Game connection established")
            ready_event.set()
            if Decode_GetLoginData.Clan_ID:
                clan_id = Decode_GetLoginData.Clan_ID
                clan_compiled_data = Decode_GetLoginData.Clan_Compiled_Data
                await create_clan_startup(clan_id, clan_compiled_data, key, iv, writer)
            while True:
                data = await reader.read(9999)
                if not data:
                    break
                with bot_tokens_lock:
                    for name, task in bot_tasks.items():
                        if task == current_task:
                            bot_last_seen[name] = time.time()
                            break
                if data.hex().startswith("12000000"):
                    response = await DecodeWhisperMessage(data.hex()[10:])
                    msg_text = response.Data.msg.strip()
                    parts = msg_text.split()
                    command = parts[0].lower() if parts else ""
                    uid = response.Data.uid
                    chat_id = response.Data.Chat_ID
                    if command == "hi":
                        message = "Hello, I am an automated bot. Type /help to see my commands."
                        if chat_id == 3037318759:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        writer.write(msg_packet)
                        await writer.drain()
                    elif command == "/help":
                        help_messages = [
                            "[FF00FF]╔══════════════════════════════╗",
                            "[FF00FF]║ [00FFFF]🤖 BOT COMMANDS MENU 🤖 [FF00FF]║",
                            "[FF00FF]╠══════════════════════════════╣",
                            "[FF00FF]║ [FFFF00]✦ /like [uid] - Send like to player",
                            "[FF00FF]║ [FFFF00]✦ /spam [uid] - Send spam friend request",
                            "[FF00FF]║ [FFFF00]✦ /team [uid] inv - Team invite",
                            "[FF00FF]║ [FFFF00]✦ /3, /5, /6, /7 [uid] - Create group",
                            "[FF00FF]║ [FFFF00]✦ /ai [question] - Chat with AI",
                            "[FF00FF]║ [FFFF00]✦ /help - Show this menu",
                            "[FF00FF]╚══════════════════════════════╝",
                            "[00FF00]Type any command to use. Enjoy! 😊"
                        ]
                        for msg in help_messages:
                            try:
                                if chat_id == 3037318759:
                                    msg_packet = await send_clan_msg(msg, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(msg, uid, key, iv)
                                writer.write(msg_packet)
                                await writer.drain()
                                await asyncio.sleep(0.5)  # Small delay between messages
                            except Exception as e:
                                print(f"Error sending help message: {e}")
                                continue
                        continue
                        if chat_id == 3037318759:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        writer.write(msg_packet)
                        await writer.drain()
                    elif command == "/team":
                        sender_uid = uid
                        if len(parts) == 3 and parts[1].isdigit() and parts[2].lower() == 'inv':
                            target_uid_to_invite = int(parts[1])
                            message = f"[FFFF00]Creating a [FF0000]5-player[FFFF00] group and inviting you and UID [FF0000]{target_uid_to_invite}[FFFF00].[FFFFFF]"
                            if chat_id == 3037318759:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, sender_uid, key, iv)
                            writer.write(msg_packet)
                            await writer.drain()
                            await create_group(bot_name, key, iv)
                            await asyncio.sleep(0.4)
                            await modify_team_player(bot_name, "4", key, iv)
                            await asyncio.sleep(0.1)
                            await invite_target(bot_name, target_uid_to_invite, bot_region, key, iv)
                            await asyncio.sleep(0.1)
                            await invite_target(bot_name, sender_uid, bot_region, key, iv)
                            await asyncio.sleep(3)
                            await left_group(bot_name, key, iv)
                        else:
                            message = "Invalid format. Use /team [uid] inv"
                            if chat_id == 3037318759:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, sender_uid, key, iv)
                            writer.write(msg_packet)
                            await writer.drain()
                    elif command.startswith(("/3", "/5", "/6", "/7")):
                        team_size_param, player_count = "", ""
                        if command.startswith("/3"):
                            team_size_param, player_count = "2", "3"
                        elif command.startswith("/5"):
                            team_size_param, player_count = "4", "5"
                        elif command.startswith("/6"):
                            team_size_param, player_count = "5", "6"
                        elif command.startswith("/7"):
                            team_size_param, player_count = "6", "7"
                        if not team_size_param: 
                            continue
                        target_uid_to_invite = uid
                        if len(parts) > 1 and parts[1].isdigit():
                            target_uid_to_invite = int(parts[1])
                        message = f"[FFFF00]Please accept my invitation to join a [FF0000]{player_count}-Player[FFFF00] group.[FFFFFF]"
                        if chat_id == 3037318759:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        writer.write(msg_packet)
                        await writer.drain()
                        await create_group(bot_name, key, iv)
                        await asyncio.sleep(0.4)
                        await modify_team_player(bot_name, team_size_param, key, iv)
                        await asyncio.sleep(0.1)
                        await invite_target(bot_name, target_uid_to_invite, bot_region, key, iv)
                        await asyncio.sleep(3)
                        await left_group(bot_name, key, iv)
                    elif command == "/ai":
                        user_input = msg_text[len("/ai"):].strip()
                        if user_input:
                            response_ai = await Get_AI_Response(user_input)
                            parts_ai = await split_text_by_words(response_ai)
                            for message in parts_ai:
                                await asyncio.sleep(1)
                                if chat_id == 3037318759:
                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(message, uid, key, iv)
                                writer.write(msg_packet)
                                await writer.drain()
                        else:
                            message = "Please Provide Some Question to proceed\nExample: /ai How Are You?"
                            if chat_id == 3037318759:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            writer.write(msg_packet)
                            await writer.drain()
                    elif command == "/like":
                        if len(parts) > 1 and parts[1].isdigit():
                            target_uid = parts[1]
                            try:
                                async with aiohttp.ClientSession() as session:
                                    url = f"https://like/public_HULULUlulululike?uid={target_uid}&region=bd"
                                    try:
                                        async with session.get(url, timeout=10) as response:

                                            if response.status == 200:
                                                data = await response.json()

                                                # Send header message first
                                                try:
                                                    header_msg = "[FF69B4]❤️ [B]LIKE STATUS[/B] ❤️"
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(header_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(header_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                                        await asyncio.sleep(0.3)
                                                except Exception as e:
                                                    pass
                                                
                                                # Send user ID
                                                try:
                                                    uid_msg = f"[00FFFF]User ID: [B]{target_uid}[/B]"
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(uid_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(uid_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                                        await asyncio.sleep(0.3)
                                                except Exception as e:
                                                    pass
                                                
                                                # Function to send a single field with error handling
                                                async def send_field(field_name, field_value):
                                                    try:
                                                        field_msg = f"[00FF7F]• {field_name}: [B]{field_value}[/B]"
                                                        if chat_id == 3037318759:
                                                            packet = await send_clan_msg(field_msg, chat_id, key, iv)
                                                        else:
                                                            packet = await send_msg(field_msg, uid, key, iv)
                                                        if packet:
                                                            writer.write(packet)
                                                            await writer.drain()
                                                            await asyncio.sleep(0.5)
                                                        return True
                                                    except Exception as e:
                                                        pass
                                                        return False
                                                
                                                # Handle API response data
                                                try:
                                                    # First check if it's an error message
                                                    if 'data' in data and 'message' in data['data']:
                                                        error_msg = f"[FF0000]❌ {data['data']['message']}"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(error_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                    else:
                                                        # Success case - send success message
                                                        success_msg = "[00FF00]✅ Like sent successfully!"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(success_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(success_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                            await asyncio.sleep(0.5)
                                                        
                                                        # Send each top-level field
                                                        for field, value in data.items():
                                                            if field not in ['status', 'success', 'data'] and not field.startswith('_'):
                                                                await send_field(field, value)
                                                        
                                                        # If there's a nested 'data' field, process its contents
                                                        if 'data' in data and isinstance(data['data'], dict):
                                                            for field, value in data['data'].items():
                                                                if field not in ['status', 'success'] and not field.startswith('_'):
                                                                    await send_field(field, value)
                                                        
                                                        # Send a completion message
                                                        completion_msg = "[FF69B4]❤️ [B]LIKE PROCESS COMPLETE[/B] ❤️"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(completion_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(completion_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                except Exception as e:
                                                    print(f"Error processing API response: {e}")
                                                    error_msg = "[FF0000]❌ An error occurred while processing the response."
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(error_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                            else:
                                                error_text = await response.text()
                                                message = f"[FF0000]❌ Error: Received status code {response.status}"
                                                if chat_id == 3037318759:
                                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                                else:
                                                    msg_packet = await send_msg(message, uid, key, iv)
                                                if msg_packet:
                                                    writer.write(msg_packet)
                                                    await writer.drain()
                                    except asyncio.TimeoutError:
                                        message = "[FF0000]❌ Error: Request timed out. Please try again later."
                                        if chat_id == 3037318759:
                                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                        else:
                                            msg_packet = await send_msg(message, uid, key, iv)
                                        if msg_packet:
                                            writer.write(msg_packet)
                                            await writer.drain()
                            except Exception as e:
                                error_msg = str(e)
                                import traceback
                                traceback.print_exc()
                                message = f"[FF0000]❌ Error: {error_msg}"
                        else:
                            message = (
                                "[FF0000]❌ Invalid format!\n"
                                "[00FF00]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                "[FFFFFF]Usage: [FFD700]/like [UID]\n"
                                "Example: [00FFFF]/like 1234567890\n"
                                "[00FF00]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            )
                            
                        if chat_id == 3037318759:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        writer.write(msg_packet)
                        await writer.drain()
                    elif command == "/spam":
                        if len(parts) > 1 and parts[1].isdigit():
                            target_uid = parts[1]
                            try:
                                async with aiohttp.ClientSession() as session:
                                    url = f"https://tcp1-two.vercel.app/spam/send_requests?uid={target_uid}&region=bd"
                                    try:
                                        async with session.get(url, timeout=10) as response:

                                            if response.status == 200:
                                                data = await response.json()

                                                # Send header message first
                                                try:
                                                    header_msg = "[FF69B4]🚀 [B]SPAM FRIEND REQUEST STATUS[/B] 🚀"
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(header_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(header_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                                        await asyncio.sleep(0.3)
                                                except Exception as e:
                                                    pass
                                                
                                                # Send user ID
                                                try:
                                                    uid_msg = f"[00FFFF]User ID: [B]{target_uid}[/B]"
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(uid_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(uid_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                                        await asyncio.sleep(0.3)
                                                except Exception as e:
                                                    pass
                                                
                                                # Function to send a single field with error handling
                                                async def send_field(field_name, field_value):
                                                    try:
                                                        field_msg = f"[00FF7F]• {field_name}: [B]{field_value}[/B]"
                                                        if chat_id == 3037318759:
                                                            packet = await send_clan_msg(field_msg, chat_id, key, iv)
                                                        else:
                                                            packet = await send_msg(field_msg, uid, key, iv)
                                                        if packet:
                                                            writer.write(packet)
                                                            await writer.drain()
                                                            await asyncio.sleep(0.5)
                                                        return True
                                                    except Exception as e:
                                                        pass
                                                        return False
                                                
                                                # Handle API response data
                                                try:
                                                    # First check if it's an error message
                                                    if 'data' in data and 'message' in data['data']:
                                                        error_msg = f"[FF0000]❌ {data['data']['message']}"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(error_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                    else:
                                                        # Success case - send success message
                                                        success_msg = "[00FF00]✅ Spam friend request sent successfully!"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(success_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(success_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                            await asyncio.sleep(0.5)
                                                        
                                                        # Send each top-level field
                                                        for field, value in data.items():
                                                            if field not in ['status', 'success', 'data'] and not field.startswith('_'):
                                                                await send_field(field, value)
                                                        
                                                        # If there's a nested 'data' field, process its contents
                                                        if 'data' in data and isinstance(data['data'], dict):
                                                            for field, value in data['data'].items():
                                                                if field not in ['status', 'success'] and not field.startswith('_'):
                                                                    await send_field(field, value)
                                                        
                                                        # Send a completion message
                                                        completion_msg = "[FF69B4]🚀 [B]SPAM FRIEND REQUEST PROCESS COMPLETE[/B] 🚀"
                                                        if chat_id == 3037318759:
                                                            msg_packet = await send_clan_msg(completion_msg, chat_id, key, iv)
                                                        else:
                                                            msg_packet = await send_msg(completion_msg, uid, key, iv)
                                                        if msg_packet:
                                                            writer.write(msg_packet)
                                                            await writer.drain()
                                                except Exception as e:
                                                    print(f"Error processing API response: {e}")
                                                    error_msg = "[FF0000]❌ An error occurred while processing the response."
                                                    if chat_id == 3037318759:
                                                        msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                                                    else:
                                                        msg_packet = await send_msg(error_msg, uid, key, iv)
                                                    if msg_packet:
                                                        writer.write(msg_packet)
                                                        await writer.drain()
                                            else:
                                                error_text = await response.text()
                                                message = f"[FF0000]❌ Error: Received status code {response.status}"
                                                if chat_id == 3037318759:
                                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                                else:
                                                    msg_packet = await send_msg(message, uid, key, iv)
                                                if msg_packet:
                                                    writer.write(msg_packet)
                                                    await writer.drain()
                                    except asyncio.TimeoutError:
                                        message = "[FF0000]❌ Error: Request timed out. Please try again later."
                                        if chat_id == 3037318759:
                                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                        else:
                                            msg_packet = await send_msg(message, uid, key, iv)
                                        if msg_packet:
                                            writer.write(msg_packet)
                                            await writer.drain()
                            except Exception as e:
                                error_msg = str(e)
                                import traceback
                                traceback.print_exc()
                                message = f"[FF0000]❌ Error: {error_msg}"
                        else:
                            message = (
                                "[FF0000]❌ Invalid format!\n"
                                "[00FF00]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                "[FFFFFF]Usage: [FFD700]/spam [UID]\n"
                                "Example: [00FFFF]/spam 1234567890\n"
                                "[00FF00]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            )
                            
                        if chat_id == 3037318759:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        writer.write(msg_packet)
                        await writer.drain()
            writer.close()
            await writer.wait_closed()
        except asyncio.CancelledError:
            print(f"TCP game connection for {bot_name} cancelled")
            break
        except Exception as e:
            print(f"Error with {ip}:{port} - {e}")
        await asyncio.sleep(reconnect_delay)

async def Get_AI_Response(user_input):
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": user_input}]}]
    }
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=payload) as response:
            if response.status == 200:
                ai_data = await response.json()
                try:
                    return ai_data['candidates'][0]['content']['parts'][0]['text']
                except (KeyError, IndexError) as e:
                    return f"Error processing AI response: {str(e)}"
            else:
                error_msg = f"[API Error] Get_AI_Response: Status {response.status}"
                print(error_msg)
                return f"Sorry to say but something wrong in AI response: {error_msg}"

# Account management functions
def load_accounts():
    try:
        with open("accounts.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_accounts(accounts):
    with open("accounts.json", "w") as f:
        json.dump(accounts, f, indent=4)

def add_account(name, uid, password):
    accounts = load_accounts()
    if any(acc["name"] == name for acc in accounts):
        return False
    accounts.append({"name": name, "uid": uid, "password": password})
    save_accounts(accounts)
    return True

def remove_account(name):
    accounts = load_accounts()
    accounts = [acc for acc in accounts if acc["name"] != name]
    save_accounts(accounts)
    return True

def update_account(name, uid=None, password=None):
    accounts = load_accounts()
    for acc in accounts:
        if acc["name"] == name:
            if uid is not None:
                acc["uid"] = uid
            if password is not None:
                acc["password"] = password
            save_accounts(accounts)
            return True
    return False

# Bot functions
async def main(bot_name, uid, password):
    open_id, access_token = await get_access_token(uid, password)
    if not open_id or not access_token:
        return None
    payload = await MajorLoginProto_Encode(open_id, access_token)
    MajorLoginResponse = await MajorLogin(payload)
    if not MajorLoginResponse:
        return None
    Decode_MajorLogin = await MajorLogin_Decode(MajorLoginResponse)
    base_url = Decode_MajorLogin.url
    token = Decode_MajorLogin.token
    with bot_tokens_lock:
        bot_tokens[bot_name] = token
    AccountUID = Decode_MajorLogin.account_uid
    key = Decode_MajorLogin.key
    iv = Decode_MajorLogin.iv
    timestamp = Decode_MajorLogin.timestamp
    GetLoginDataResponse = await GetLoginData(base_url, payload, token)
    if not GetLoginDataResponse:
        return None
    Decode_GetLoginData = await GetLoginData_Decode(GetLoginDataResponse)
    bot_region = Decode_GetLoginData.Region
    Online_IP_Port = Decode_GetLoginData.Online_IP_Port
    AccountIP_Port = Decode_GetLoginData.AccountIP_Port
    online_ip, online_port = Online_IP_Port.split(":")
    account_ip, account_port = AccountIP_Port.split(":")
    encrypted_startup = await get_encrypted_startup(int(AccountUID), token, int(timestamp), key, iv)
    ready_event = asyncio.Event()
    task1 = asyncio.create_task(
        handle_tcp_connection(account_ip, account_port, encrypted_startup, key, iv, Decode_GetLoginData, ready_event, bot_region, bot_name)
    )
    await ready_event.wait()
    await asyncio.sleep(2)
    task2 = asyncio.create_task(
        handle_tcp_online_connection(online_ip, online_port, encrypted_startup, bot_name)
    )
    await asyncio.gather(task1, task2)

async def start_bot(bot_name, uid, password):
    try:
        await asyncio.wait_for(main(bot_name, uid, password), timeout=TOKEN_EXPIRY_SECONDS)
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"Error starting bot {bot_name}: {str(e)}")

async def run_forever(bot_name, uid, password):
    while True:
        try:
            await start_bot(bot_name, uid, password)
        except asyncio.CancelledError:
            print(f"Bot {bot_name} task cancelled")
            # Clean up resources
            with bot_tokens_lock:
                bot_tasks.pop(bot_name, None)
                bot_tokens.pop(bot_name, None)
                bot_last_seen.pop(bot_name, None)
                if bot_name in bot_online_writers:
                    writer = bot_online_writers.pop(bot_name)
                    writer.close()
                    await writer.wait_closed()
            break
        except Exception as e:
            print(f"Error in bot {bot_name}: {str(e)}")
        await asyncio.sleep(2)

# Queue for bot actions
bot_action_queue = asyncio.Queue()

async def bot_action_processor():
    while True:
        action, args = await bot_action_queue.get()
        try:
            if action == 'start':
                name, uid, password = args
                if name not in bot_tasks:
                    task = asyncio.create_task(run_forever(name, uid, password))
                    with bot_tokens_lock:
                        bot_tasks[name] = task
                        bot_last_seen[name] = time.time()
            elif action == 'stop':
                name = args
                if name in bot_tasks:
                    bot_tasks[name].cancel()
                    try:
                        await bot_tasks[name]
                    except asyncio.CancelledError:
                        pass
                    with bot_tokens_lock:
                        bot_tasks.pop(name, None)
                        bot_tokens.pop(name, None)
                        bot_last_seen.pop(name, None)
                        if name in bot_online_writers:
                            writer = bot_online_writers.pop(name)
                            writer.close()
                            await writer.wait_closed()
        except Exception as e:
            print(f"Error processing bot action {action} for {args}: {str(e)}")
        finally:
            bot_action_queue.task_done()

# Flask routes
@app.route("/send_requests", methods=["GET"])
def send_requests():
    bot_name = request.args.get("bot_name")
    uid = request.args.get("uid")
    if not bot_name or not uid:
        return jsonify({"message": "bot_name and uid parameters are required"})
    with bot_tokens_lock:
        token = bot_tokens.get(bot_name)
    if not token:
        return jsonify({"message": f"No token found for bot {bot_name}"})
    encrypted_id = encode_uid(uid)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)
    url = API_ENDPOINTS['ADD_FRIEND']
    headers = _get_headers(token)
    response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload))
    if response.status_code == 200:
        return jsonify({"message": f"Successfully sent friend request to {uid} using bot {bot_name}"})
    else:
        return jsonify({"message": f"Failed to send friend request to {uid} using bot {bot_name}", "status_code": response.status_code})

@app.route("/remove_friend", methods=["GET"])
def remove_friend():
    bot_name = request.args.get("bot_name")
    uid = request.args.get("uid")
    if not bot_name or not uid:
        return jsonify({"message": "bot_name and uid parameters are required"})
    with bot_tokens_lock:
        token = bot_tokens.get(bot_name)
    if not token:
        return jsonify({"message": f"No token found for bot {bot_name}"})
    encrypted_id = encode_uid(uid)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)
    url = API_ENDPOINTS['REMOVE_FRIEND']
    headers = _get_headers(token)
    response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload))
    if response.status_code == 200:
        return jsonify({"message": f"Successfully removed {uid} from friendlist using bot {bot_name}"})
    else:
        return jsonify({"message": f"Failed to remove {uid} from friendlist using bot {bot_name}", "status_code": response.status_code})

@app.route("/add_account", methods=["GET"])
def add_account_route():
    name = request.args.get("name")
    uid = request.args.get("uid")
    password = request.args.get("password")
    if not all([name, uid, password]):
        return jsonify({"message": "Missing parameters: name, uid, and password are required"})
    if add_account(name, uid, password):
        bot_action_queue.put_nowait(('start', (name, uid, password)))
        return jsonify({"message": f"Account {name} added and bot start requested"})
    else:
        return jsonify({"message": f"Account {name} already exists"})

@app.route("/remove_account", methods=["GET"])
def remove_account_route():
    name = request.args.get("name")
    if not name:
        return jsonify({"message": "Missing name parameter"})
    if remove_account(name):
        bot_action_queue.put_nowait(('stop', name))
        return jsonify({"message": f"Account {name} removed and bot stop requested"})
    else:
        return jsonify({"message": f"Account {name} not found"})

@app.route("/update_account", methods=["GET"])
def update_account_route():
    name = request.args.get("name")
    uid = request.args.get("uid")
    password = request.args.get("password")
    if not name:
        return jsonify({"message": "Missing name parameter"})
    if not uid and not password:
        return jsonify({"message": "At least one of uid or password must be provided to update"})
    if update_account(name, uid, password):
        accounts = load_accounts()
        account = next((acc for acc in accounts if acc["name"] == name), None)
        if account:
            bot_action_queue.put_nowait(('stop', name))
            bot_action_queue.put_nowait(('start', (name, account["uid"], account["password"])))
            return jsonify({"message": f"Account {name} updated and bot restart requested"})
        else:
            return jsonify({"message": f"Account {name} not found after update"})
    else:
        return jsonify({"message": f"Account {name} not found"})

@app.route('/')
def index():
    return 'Bot is running! Use /status to check account statuses.'

@app.route('/status')
def status():
    accounts = load_accounts()
    status_list = []
    current_time = time.time()
    
    for account in accounts:
        name = account['name']
        uid = account['uid']
        
        if name in bot_tasks and name in bot_last_seen:
            last_seen = current_time - bot_last_seen[name]
            if last_seen < 60:
                status = "🟢 ONLINE"
                last_seen_str = f"{int(last_seen)} seconds ago"
            else:
                status = "🟡 IDLE"
                last_seen_str = f"{int(last_seen//60)} minutes ago"
        else:
            status = "🔴 OFFLINE"
            last_seen_str = "Never"
        
        status_list.append({
            'name': name,
            'uid': uid,
            'status': status,
            'last_seen': last_seen_str
        })
    
    online_count = len([s for s in status_list if 'ONLINE' in s['status']])
    idle_count = len([s for s in status_list if 'IDLE' in s['status']])
    offline_count = len([s for s in status_list if 'OFFLINE' in s['status']])
    
    html = ["""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bot Status</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .status-card {
                background: #f8f9fa;
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .online { color: #28a745; }
            .offline { color: #dc3545; }
            .idle { color: #ffc107; }
            .last-seen { color: #6c757d; font-size: 0.9em; }
            .total { margin: 20px 0; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🤖 Bot Status Dashboard</h1>
        <div class="total">
            Total Accounts: %d | Online: %d | Idle: %d | Offline: %d
        </div>
    """ % (len(status_list), online_count, idle_count, offline_count)]
    
    for account in status_list:
        status_class = account['status'].split(' ')[0].lower()
        html.append(f"""
        <div class="status-card">
            <div class="name"><strong>{account['name']}</strong> ({account['uid']})</div>
            <div class="status {status_class}">{account['status']}</div>
            <div class="last-seen">Last seen: {account['last_seen']}</div>
        </div>""")
    
    html.append(f"""
        <div style="margin-top: 30px; color: #6c757d; font-size: 0.8em;">
            Last updated: {time.strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </body>
    </html>""")
    
    return '\n'.join(html)

def run_flask_app():
    app.run(host="0.0.0.0", port=5000)

async def monitor_bots():
    """Background task to check and restart offline bots every 30 seconds"""
    while True:
        try:
            accounts = {acc["name"]: acc for acc in load_accounts()}
            current_time = time.time()
            
            for name, account in accounts.items():
                try:
                    if (name not in bot_tasks or 
                            name not in bot_last_seen or 
                            current_time - bot_last_seen.get(name, 0) > 60):
                        print(f"Bot {name} appears offline. Attempting to restart...")
                        bot_action_queue.put_nowait(('stop', name))
                        bot_action_queue.put_nowait(('start', (name, account["uid"], account["password"])))
                except Exception as e:
                    print(f"Error monitoring bot {name}: {str(e)}")
            
            for name in list(bot_tasks.keys()):
                if name not in accounts:
                    print(f"Removing bot {name} as it's no longer in accounts.json")
                    bot_action_queue.put_nowait(('stop', name))
            
        except Exception as e:
            print(f"Error in monitor_bots: {str(e)}")
        
        await asyncio.sleep(30)

async def main_async():
    print("Loading accounts...")
    accounts = load_accounts()
    if not accounts:
        print("No accounts found in accounts.json")
        return
        
    print(f"Found {len(accounts)} accounts")
    tasks = []
    
    tasks.append(asyncio.create_task(bot_action_processor()))
    tasks.append(asyncio.create_task(monitor_bots()))
    
    for account in accounts:
        try:
            name = account["name"]
            uid = account["uid"]
            password = account["password"]
            print(f"Starting bot for account: {name}")
            task = asyncio.create_task(run_forever(name, uid, password))
            with bot_tokens_lock:
                bot_tasks[name] = task
                bot_last_seen[name] = time.time()
            tasks.append(task)
        except Exception as e:
            print(f"Error starting bot for account {account.get('name', 'unknown')}: {str(e)}")
    
    if len(tasks) == 2:
        print("No bot tasks were created. Check your accounts.json file.")
        return
        
    print("All bots started. Press Ctrl+C to stop.")
    print("Monitoring bots every 30 seconds...")
    
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        print("Shutting down bots...")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == '__main__':
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()
    asyncio.run(main_async())