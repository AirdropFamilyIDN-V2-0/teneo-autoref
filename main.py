import random
import string
import asyncio
import logging
from bs4 import BeautifulSoup
from faker import Faker
import re
import names
from dotenv import load_dotenv
import os
from curl_cffi import requests
import time
from urllib.parse import urlencode
import websockets
from eth_account import Account
from eth_account.messages import encode_defunct
import secrets
import logging
import aiohttp
import json

class Captcha:
    def __init__(self, api_key):
        self.url = 'https://api.sctg.xyz/'
        self.key = api_key + "|SOFTID6953912161" if api_key else None
        self.provider = "Xevil"

        if not self.key:
            raise ValueError("API Key cannot be empty. Please provide a valid key.")

    def in_api(self, content, method, header=None):
        params = f"key={self.key}&json=1&{content}"
        headers = {'Content-Type': 'application/json'} if header else {}

        try:
            if method == "GET":
                response = requests.get(f"{self.url}in.php?{params}")
            else:
                response = requests.post(f"{self.url}in.php", data=params, headers=headers)

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error with HTTP request: {e}")
            return None
        except requests.exceptions.JSONDecodeError:
            print("Error decoding JSON response.")
            return None

    def res_api(self, api_id):
        params = f"?key={self.key}&action=get&id={api_id}&json=1"
        try:
            response = requests.get(f"{self.url}res.php{params}", timeout=60)  # Increase timeout
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching captcha result: {e}")
            return None

    def solving_progress(self, xr, tmr, cap):
        symbols = [' ─ ', ' / ', ' │ ', ' ']
        a = 0
        for _ in range(tmr * 2):  # Kurangi waktu tunggu untuk mempercepat proses
            print(f"Bypass {cap} {xr}%{symbols[a % 4]}\r", end="")
            time.sleep(0.05)  # Kurangi waktu tidur untuk mempercepat proses
            if xr < 99:
                xr += 1
            a += 1
        return xr

    def get_result(self, data, method, header=None):
        cap = self.filter_method(data.split('method=')[1].split('&')[0])
        get_res = self.in_api(data, method, header)

        # Log the response from in_api
        logging.info(f"[*] in_api response: {get_res}")

        if not get_res or not get_res.get("status"):
            msg = get_res.get("request", "Something went wrong") if get_res else "No response"
            print(f"Error: in_api @{self.provider} {msg}")
            return None

        api_id = get_res["request"]
        a = 0

        while True:
            print(f"Bypass {cap} {a}% |   \r", end="")
            result = self.res_api(api_id)

            if not result:
                print(f"[!] Failed to fetch result for {cap}")
                return None

            if result.get("request") == "CAPCHA_NOT_READY":
                a = min(a + random.randint(10, 20), 99)  # Tambahkan lebih banyak persen untuk mempercepat proses
                a = self.solving_progress(a, 2, cap)  # Kurangi waktu tunggu untuk mempercepat proses
                time.sleep(10)  # Kurangi waktu tunggu untuk mempercepat proses
                continue

            if result.get("status"):
                print(f"Bypass {cap} 100%\r")
                time.sleep(0.5)  # Kurangi waktu tidur untuk mempercepat proses
                print(f"[!] Bypass {cap} success")
                return result["request"]

            print(f"[!] Bypass {cap} failed")
            return None

    def filter_method(self, method):
        mapping = {
            "userrecaptcha": "RecaptchaV2",
            "hcaptcha": "Hcaptcha",
            "turnstile": "Turnstile",
            "universal": "Ocr",
            "base64": "Ocr",
            "antibot": "Antibot",
            "authkong": "Authkong",
            "teaserfast": "Teaserfast"
        }
        return mapping.get(method, method)

    def get_balance(self):
        try:
            response = requests.get(f"{self.url}res.php?action=userinfo&key={self.key}")
            response.raise_for_status()
            return response.json().get("balance")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching balance: {e}")
            return None

    def recaptcha_v2(self, sitekey, pageurl):
        if not sitekey or not pageurl:
            print("Sitekey and pageurl must not be empty.")
            return None

        data = urlencode({"method": "userrecaptcha", "sitekey": sitekey, "pageurl": pageurl})
        return self.get_result(data, "GET")

    def hcaptcha(self, sitekey, pageurl):
        data = urlencode({"method": "hcaptcha", "sitekey": sitekey, "pageurl": pageurl})
        return self.get_result(data, "GET")

    def turnstile(self, sitekey, pageurl):
        """Solves a Turnstile CAPTCHA via the service."""
        data = urlencode({"method": "turnstile", "sitekey": sitekey, "pageurl": pageurl})
        result = self.get_result(data, "GET")

        # Log the raw result received
        logging.info(f"[*] turnstile raw result: {result}")

        # Check if the result is valid
        if result is None:
            raise ValueError("Failed to solve CAPTCHA. No valid response received.")

        # If the result is a string, we may need to parse it
        if isinstance(result, str):
            # Assuming the result is a base64 encoded string or similar, handle accordingly
            # You may need to decode or process the string based on your API's documentation
            # For now, let's just log it and return it as is
            return result  # Or process it further if needed

        # Check if 'status' is in the result and equals 1
        if 'status' not in result or result['status'] != 1:
            raise ValueError("CAPTCHA solving failed. No valid request ID returned.")

        # Return the request ID if everything is valid
        return result.get('request')

    def ocr(self, img):
        data = f"method=base64&body={img}"
        return self.get_result(data, "POST")

    def antibot(self, source):
        main = source.split('data:image/png;base64,')[1].split('"')[0]
        if not main:
            return None

        data = f"method=antibot&main={main}"
        return self.get_result(data, "POST")


load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load API keys from environment variables
X_API_KEY = os.getenv("X_API_KEY", "YOUR_X_API_KEY")

def generate_email(domain):
    first_name = names.get_first_name().lower()
    last_name = names.get_last_name().lower()
    random_nums = ''.join(random.choices(string.digits, k=3))
    email = f"{first_name}{last_name}{random_nums}@{domain}"
    logging.info(f"[*] Generated email: {email}")
    return email

def generate_password():
    length = 12  # Total length of the password
    upper = random.choice(string.ascii_uppercase)
    lower = ''.join(random.choices(string.ascii_lowercase, k=8))
    digits = ''.join(random.choices(string.digits, k=2))
    special = '@'
    password = upper + lower + digits + special
   # logging.info(f"[*] Generated password: {password}")
    return password

async def get_domains(max_retries=5):
    for attempt in range(max_retries):
        try:
            key = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=2))
          #  logging.info(f"[*] Fetching domains with key: {key}")
            response = requests.get(f"https://generator.email/search.php?key={key}", timeout=30)

            if response.ok:
                json_data = response.json()
                if isinstance(json_data, list) and json_data:
                    return json_data
          #  logging.warning("[!] Empty or invalid domain list.")
        except requests.exceptions.RequestException as error:
            logging.error(f"[!] Error fetching domains: {error}")
        await asyncio.sleep(2)

    return []

async def get_otp(email, max_retries=3):
    email_username, email_domain = email.split('@')
    cookies = {'embx': f'[%22{email}%22]', 'surl': f'{email_domain}/{email_username}'}
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    }

    for inbox_num in range(1, 4):
        for attempt in range(max_retries):
            try:
                logging.info(f"[*] Checking inbox {inbox_num} (Attempt {attempt + 1})...")
                response = requests.get(f"https://generator.email/inbox{inbox_num}/", headers=headers, cookies=cookies, timeout=30)
                
                if response.status_code != 200:
                   # logging.warning(f"[!] Received non-200 status code: {response.status_code}")
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                email_body = soup.get_text()

               # logging.info(f"[*] Email content: {email_body}")

                otp_match = re.search(r'\b(\d{6})\b', email_body)  # Updated regex to capture the OTP
                if otp_match:
                    otp = otp_match.group(1)
                    logging.info(f"[*] OTP extracted successfully: {otp}")
                    return otp
                logging.warning("[!] OTP not found in email content.")

            except requests.exceptions.RequestException as error:
                logging.error(f"[!] Error checking inbox {inbox_num}: {error}")

            await asyncio.sleep(20)  # Tunggu 15 detik

    return None

def load_proxies(filename='proxy.txt'):
    try:
        with open(filename, 'r') as file:
            proxies = [proxy.strip() for proxy in file.readlines() if proxy.strip()]
            return proxies
    except FileNotFoundError:
        logging.error(f"[!] Proxy file '{filename}' not found.")
        return []

async def register_account(email, password, invited_by, api_key, gunakan_proxy):
    sitekey = "0x4AAAAAAAkhmGkb2VS6MRU0"
    siteurlregister = "https://dashboard.teneo.pro/auth/signup"

    # Create an instance of the Captcha class with the API key
    captcha_solver = Captcha(api_key)
    captcha_response = captcha_solver.turnstile(sitekey, siteurlregister)

    if not captcha_response:
        logging.error("[!] CAPTCHA solving failed, cannot proceed with registration.")
        return {"message": "CAPTCHA solving failed"}

    url = "https://auth.teneo.pro/api/signup"
    payload = {
        "email": email,
        "password": password,
        "invitedBy": invited_by,
        "turnstileToken": captcha_response
    }
    headers = {"content-type": "application/json", "x-api-key": X_API_KEY}

    logging.info(f"[*] Registering account with email: {email}")

    proxies = load_proxies()
    chosen_proxy = random.choice(proxies) if proxies and gunakan_proxy else None
    proxy_dict = {"http": chosen_proxy, "https": chosen_proxy} if chosen_proxy else None

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers, proxy=proxy_dict["http"] if gunakan_proxy and proxy_dict else None) as response:
            logging.info(f"[*] Response status code: {response.status}")
            logging.info(f"[*] Response text: {await response.text()}")

            try:
                return await response.json()
            except aiohttp.ClientError as e:
                logging.error("[!] Failed to parse JSON response.")
                return {"error": "Invalid response"}

async def register_verification_code(token, verification_code, gunakan_proxy):
    url = "https://auth.teneo.pro/api/verify-email"
    payload = {"token": token, "verificationCode": verification_code}
    headers = {"content-type": "application/json", "x-api-key": X_API_KEY}

    logging.info("[*] Sending verification code...")

    proxies = load_proxies()
    chosen_proxy = random.choice(proxies) if proxies and gunakan_proxy else None
    proxy_dict = {"http": chosen_proxy, "https": chosen_proxy} if chosen_proxy else None

    max_retries = 3  # Number of retries
    for attempt in range(max_retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers, proxy=proxy_dict["http"] if gunakan_proxy else None) as response:
                    response.raise_for_status()  # Raise an error for bad responses
                    response_json = await response.json()  # Ensure this is a JSON object
                    if isinstance(response_json, dict) and "error" in response_json:
                        logging.error(f"[!] Attempt {attempt + 1} failed: {response_json['error']}")

                        if response_json["error"] == "Invalid verification code":
                            return {"error": "Invalid verification code"}

                        if response_json["error"] == "Account already verified":
                            return {"error": "Account already verified"}

                    return response_json
        except aiohttp.ClientError as e:
            logging.error(f"[!] Attempt {attempt + 1} failed: {e}")
            await asyncio.sleep(2)  # Wait before retrying
        except json.JSONDecodeError:
            logging.error("[!] Failed to parse JSON response.")
            return {"error": "Invalid response"}
        except Exception as e:
            logging.error(f"[!] Unexpected error: {e}")
            return {"error": str(e)}

    logging.error("[!] All attempts to send the verification code failed.")
    return {"error": "Failed to send verification code after retries."}

async def farming(access_token):
    url = f"wss://secure.ws.teneo.pro/websocket?accessToken={access_token}&version=v0.2"
    
    async with websockets.connect(url) as websocket:
        # Send a PING message once
        await websocket.send('{"type":"PING"}')
        logging.info("[*] PING message sent.")

        # Wait for a response
        response = await websocket.recv()
        logging.info(f"[*] Message received: {response}")

def generate_ethereum_wallet():
    private_key = '0x' + secrets.token_hex(32)
    account = Account.from_key(private_key)
    return {
        'address': account.address,
        'private_key': private_key
    }
def create_wallet_signature(wallet, message):
    # Create a signature using the wallet's private key
    account = Account.from_key(wallet['private_key'])
    signed_message = account.sign_message(encode_defunct(text=message))
    return signed_message.signature.hex()

def log_message(message, level):
    if level == "process":
        logging.info(f"[PROCESS] {message}")
    elif level == "success":
        logging.info(f"[SUCCESS] {message}")
    elif level == "error":
        logging.error(f"[ERROR] {message}")
    elif level == "warning":
        logging.warning(f"[WARNING] {message}")
    elif level == "info":
        logging.info(f"[INFO] {message}")

async def link_wallet(access_token, email):
    logging.info("[*] Generating wallet and linking...")
    
    wallet = generate_ethereum_wallet()
    
    message = f"Permanently link wallet to Teneo account: {email}. This can only be done once."
    signature = create_wallet_signature(wallet, message)
    
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Authorization': f'Bearer {access_token}',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://dashboard.teneo.pro',
        'Referer': 'https://dashboard.teneo.pro/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
    }
    
    if not signature.startswith('0x'):
        signature = '0x' + signature
    
    link_data = {
        "address": wallet['address'],
        "signature": signature,
        "message": message
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post('https://api.teneo.pro/api/users/link-wallet', headers=headers, json=link_data, timeout=60) as response:
                response.raise_for_status()  # Raise an error for bad responses
                response_json = await response.json()  # Ensure this is a JSON object
                if isinstance(response_json, dict) and "success" in response_json:
                    logging.info(f"[*] {response_json.get('message')}: {wallet['address']}")
                    return wallet
                else:
                    logging.error(f"{response_json.get('message', 'Unknown error')}")
                    return None
    except aiohttp.ClientError as e:
        logging.error(f"Error linking wallet: {e}")
        return None

async def main():
    print("Teneo Auto Referral By @AirdropFamilyIDN")
    print("[*] Register api_key      : https://t.me/Xevil_check_bot?start=6953912161")
    api_key = input("[*] Enter your API Key    : ")
    invited_by = input("[*] Input your invite code: ")
    jumlah_interasi = int(input("[*] Mau Berapa Referral   : "))
    gunakan_proxy = input("[*] Gunakan proxy? (y/n)  : ").lower() == 'y'
    
    domains = await get_domains()
    if not domains:
        logging.error("[!] Failed to fetch domains!")
        return

    total_sukses = 0
    total_gagal = 0
    for _ in range(jumlah_interasi):
        print(f"\n[*] Proses Referral {_+1}/{jumlah_interasi}")
        domain = random.choice(domains)
        email = generate_email(domain)
        password = generate_password()

        response = await register_account(email, password, invited_by, api_key, gunakan_proxy)

        token = response.get('token')
        if not token:
            logging.error("[!] No token received. Registration failed.")
            total_gagal += 1
            continue

        otp = await get_otp(email)
        if otp:
            verification_response = await register_verification_code(token, otp, gunakan_proxy)
            if isinstance(verification_response, dict):
                access_token = verification_response.get('access_token')
                if access_token:
                    wallet = await link_wallet(access_token, email)
                    if wallet:
                        with open("akuns.txt", "a") as f:
                            f.write(f"{email}:{password}:{access_token}:{wallet['private_key']}\n")
                            f.flush()
                            logging.info("[*] Referral Sukses...")
                            logging.info("[*] Access token and private key saved to akuns.txt")
                        total_sukses += 1
                        await farming(access_token)
            else:
                logging.error(f"[!] Verification failed: {verification_response}")
                total_gagal += 1

    print()
    logging.info(f"[*] Total referral sukses: {total_sukses}")
    logging.info(f"[*] Total referral gagal : {total_gagal}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logging.error(f"[!] An error occurred: {e}")
