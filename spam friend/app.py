from flask import Flask, request, jsonify
import os
import requests
import json
import threading
from byte import Encrypt_ID, encrypt_api
import asyncio
import aiohttp
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)

# Function to load tokens from external API
def validate_token(token):
    """Quick validation to check if token format is valid"""
    try:
        # Basic JWT format check
        if not token or len(token.split('.')) != 3:
            return False
        
        # Check if token is not too old (basic check)
        import base64
        import time
        
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Decode payload
        payload = parts[1]
        # Add padding if needed
        payload += '=' * (4 - len(payload) % 4)
        
        try:
            decoded = base64.b64decode(payload).decode('utf-8')
            payload_data = json.loads(decoded)
            
            # Check expiration
            if 'exp' in payload_data:
                current_time = int(time.time())
                if payload_data['exp'] < current_time:
                    return False
                    
            return True
        except:
            return False
    except:
        return False

def load_tokens(region: str = "bd"):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        token_path = os.path.join(base_dir, f"token_{region}.json")
        with open(token_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            tokens = [item["token"] for item in data]
            
            # Filter out invalid tokens
            valid_tokens = [token for token in tokens if validate_token(token)]
            invalid_count = len(tokens) - len(valid_tokens)
            
            if invalid_count > 0:
                print(f"Filtered out {invalid_count} invalid/expired tokens")
                
            return valid_tokens
    except Exception as e:
        print(f"Error loading tokens from token_{region}.json: {e}")
        return []

# Encryption functions for player info
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

async def get_player_info(uid, token):
    try:
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return None
            
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypted_uid)
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, ssl=False) as response:
                if response.status != 200:
                    return None
                hex_data = await response.read()
                binary = bytes.fromhex(hex_data.hex())
                items = like_count_pb2.Info()
                items.ParseFromString(binary)
                jsone = MessageToJson(items)
                data_info = json.loads(jsone)
                return str(data_info.get('AccountInfo', {}).get('PlayerNickname', ''))
    except:
        return None

def send_friend_request(uid, token, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        if not encrypted_id:
            results["failed"] += 1
            return
            
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        if not encrypted_payload:
            results["failed"] += 1
            return

        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }

        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)

        if response.status_code == 200:
            results["success"] += 1
        elif response.status_code == 401:
            # Token expired or invalid
            results["failed"] += 1
            print(f"Token expired/invalid: HTTP 401 for UID {uid}")
            # Add to expired tokens list for cleanup
            if "expired_tokens" not in results:
                results["expired_tokens"] = []
            results["expired_tokens"].append(token)
        else:
            results["failed"] += 1
            print(f"Friend request failed: HTTP {response.status_code} for UID {uid} - {response.text[:100]}")
    except Exception as e:
        results["failed"] += 1
        print(f"Exception in friend request for UID {uid}: {e}")

@app.route("/send_requests", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    region = (request.args.get("region") or "bd").lower()
    
    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    tokens = load_tokens(region)
    if not tokens:
        return jsonify({"error": f"No tokens found for region '{region}'"}), 500

    # Check if all tokens are expired
    expired_count = 0
    for token in tokens:
        if not validate_token(token):
            expired_count += 1
    
    if expired_count == len(tokens):
        print("All tokens are expired! Triggering token refresh...")
        # Try to trigger token refresh via GitHub API
        try:
            import requests
            refresh_url = f"https://api.github.com/repos/nicchenxgod067/tcp1/actions/workflows/token-update.yml/dispatches"
            headers = {
                "Authorization": f"token {os.getenv('GITHUB_TOKEN', '')}",
                "Accept": "application/vnd.github.v3+json"
            }
            payload = {
                "ref": "main",
                "inputs": {"region": region}
            }
            response = requests.post(refresh_url, headers=headers, json=payload, timeout=10)
            if response.status_code == 204:
                print("Token refresh triggered successfully")
                return jsonify({
                    "message": "Tokens expired. Token refresh triggered. Please try again in 2-3 minutes.",
                    "status": 3
                }), 200
        except Exception as e:
            print(f"Failed to trigger token refresh: {e}")

    # Get player name (using first token)
    player_name = asyncio.run(get_player_info(uid, tokens[0]))

    results = {"success": 0, "failed": 0}
    threads = []

    for token in tokens[:100]:  # Limit to 100 requests
        thread = threading.Thread(target=send_friend_request, args=(uid, token, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    total_requests = results["success"] + results["failed"]
    status = 1 if results["success"] != 0 else 2  # 1 if success, 2 if all failed

    response_data = {
        "success_count": results["success"],
        "failed_count": results["failed"],
        "status": status
    }
    
    if player_name:
        response_data["player_name"] = player_name

    return jsonify(response_data)

@app.route("/test_token", methods=["GET"])
def test_token():
    """Test a single token to see if it works"""
    region = (request.args.get("region") or "bd").lower()
    tokens = load_tokens(region)
    if not tokens:
        return jsonify({"error": f"No tokens found for region '{region}'"}), 500
    
    # Test first token
    test_token = tokens[0]
    test_uid = "13038762931"  # Your target UID
    
    try:
        encrypted_id = Encrypt_ID(test_uid)
        if not encrypted_id:
            return jsonify({"error": "Failed to encrypt UID"}), 500
            
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        if not encrypted_payload:
            return jsonify({"error": "Failed to encrypt payload"}), 500

        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {test_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }

        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)
        
        return jsonify({
            "status_code": response.status_code,
            "response_text": response.text[:200] if response.text else "No response text",
            "headers": dict(response.headers),
            "encrypted_uid": encrypted_id,
            "encrypted_payload": encrypted_payload
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
