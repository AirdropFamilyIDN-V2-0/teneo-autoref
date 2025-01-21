import requests
import json
import random
import string
import names
import time
import secrets
from datetime import datetime
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from eth_account import Account
from eth_account.messages import encode_defunct
import asyncio
import websockets
import aiofiles
import sys
import os

init(autoreset=True)

def log_message(account_num=None, total=None, message="", message_type="info"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    account_status = f"{account_num}/{total}" if account_num and total else ""
    
    colors = {
        "info": Fore.LIGHTWHITE_EX,
        "success": Fore.LIGHTGREEN_EX,
        "error": Fore.LIGHTRED_EX,
        "warning": Fore.LIGHTYELLOW_EX,
        "process": Fore.LIGHTCYAN_EX,
        "debug": Fore.LIGHTMAGENTA_EX
    }
    
    log_color = colors.get(message_type, Fore.LIGHTWHITE_EX)
    print(f"{Fore.WHITE}[{Style.DIM}{timestamp}{Style.RESET_ALL}{Fore.WHITE}] "
          f"{Fore.WHITE}[{Fore.LIGHTYELLOW_EX}{account_status}{Fore.WHITE}] "
          f"{log_color}{message}")

def generate_ethereum_wallet():
    private_key = '0x' + secrets.token_hex(32)
    account = Account.from_key(private_key)
    return {
        'address': account.address,
        'private_key': private_key
    }

def create_wallet_signature(wallet, message):
    account = Account.from_key(wallet['private_key'])
    signable_message = encode_defunct(text=message)
    signed_message = account.sign_message(signable_message)
    return signed_message.signature.hex()

class TeneoAutoref:
    def __init__(self, ref_code):
        self.ua = UserAgent()
        self.session = requests.Session()
        self.ref_code = ref_code
        self.socket = None
        self.ping_interval = None
        self.countdown_interval = None
        self.potential_points = 0
        self.countdown = "Calculating..."
        self.points_total = 0
        self.points_today = 0
    
    def make_request(self, method, url, **kwargs):
        try:
            #log_message(self.current_num, self.total, f"Making {method} request to {url}", "debug")
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            log_message(self.current_num, self.total, f"Request failed: {str(e)}", "error")
            return None

    def get_random_domain(self):
        log_message(self.current_num, self.total, "Searching for available email domain...", "process")
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        keyword = random.choice(consonants) + random.choice(vowels)
        
        headers = {'User-Agent': self.ua.random}
        response = self.make_request('GET', f'https://generator.email/search.php?key={keyword}', headers=headers, timeout=60)
        
        if not response:
            return None
            
        domains = response.json()
        valid_domains = [d for d in domains if all(ord(c) < 128 for c in d)]
        
        if valid_domains:
            selected_domain = random.choice(valid_domains)
            log_message(self.current_num, self.total, f"Selected domain: {selected_domain}", "success")
            return selected_domain
            
        log_message(self.current_num, self.total, "Could not find valid domain", "error")
        return None

    def generate_email(self, domain):
        log_message(self.current_num, self.total, "Generating email address...", "process")
        first_name = names.get_first_name().lower()
        last_name = names.get_last_name().lower()
        random_nums = ''.join(random.choices(string.digits, k=3))
        
        separator = random.choice(['', '.'])
        email = f"{first_name}{separator}{last_name}{random_nums}@{domain}"
        log_message(self.current_num, self.total, f"Email created: {email}", "success")
        return email

    def generate_password(self):
        log_message(self.current_num, self.total, "Generating password...", "process")
        first_letter = random.choice(string.ascii_uppercase)
        lower_letters = ''.join(random.choices(string.ascii_lowercase, k=4))
        numbers = ''.join(random.choices(string.digits, k=3))
        password = f"{first_letter}{lower_letters}@{numbers}"
        log_message(self.current_num, self.total, "Password created successfully", "success")
        return password

    def check_user_exists(self, email):
        log_message(self.current_num, self.total, "Checking email availability...", "process")
        headers = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "x-api-key": "OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjA",
            "user-agent": self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'
        }
        check_url = "https://auth.teneo.pro/api/check-user-exists"
        response = self.make_request('POST', check_url, headers=headers, json={"email": email}, timeout=60)
        
        if not response:
            return True
            
        exists = response.json().get("exists", True)
        
        if exists:
            log_message(self.current_num, self.total, "Email already registered", "error")
        else:
            log_message(self.current_num, self.total, "Email is available", "success")
        return exists

    def generate_valid_credentials(self):
        max_attempts = 5
        for attempt in range(max_attempts):
            domain = self.get_random_domain()
            if not domain:
                continue

            email = self.generate_email(domain)
            if not self.check_user_exists(email):
                return domain, email, self.generate_password()
            
            log_message(self.current_num, self.total, f"Retrying with new credentials (Attempt {attempt + 1}/{max_attempts})", "warning")
        
        return None, None, None

    def register_account(self, email, password):
        log_message(self.current_num, self.total, "Registering account...", "process")
        headers = {
            "accept": "*/*",
            "content-type": "application/json;charset=UTF-8",
            "apikey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlra25uZ3JneHV4Z2pocGxicGV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjU0MzgxNTAsImV4cCI6MjA0MTAxNDE1MH0.DRAvf8nH1ojnJBc3rD_Nw6t1AV8X_g6gmY_HByG2Mag",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlra25uZ3JneHV4Z2pocGxicGV5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjU0MzgxNTAsImV4cCI6MjA0MTAxNDE1MH0.DRAvf8nH1ojnJBc3rD_Nw6t1AV8X_g6gmY_HByG2Mag",
            "user-agent": self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'            
        }
        
        register_data = {
            "email": email,
            "password": password,
            "data": {"invited_by": self.ref_code},
            "gotrue_meta_security": {},
            "code_challenge": None,
            "code_challenge_method": None
        }
        
        # Update URL to include redirect_to parameter
        register_url = "https://node-b.teneo.pro/auth/v1/signup?redirect_to=https%3A%2F%2Fdashboard.teneo.pro%2Fauth%2Fverify"
        response = self.make_request('POST', register_url, headers=headers, json=register_data, timeout=60)
        
        if not response:
            return {"role": None}
            
        result = response.json()
        
        if result.get("role") == "authenticated":
            log_message(self.current_num, self.total, "Registration successful", "success")
        else:
            log_message(self.current_num, self.total, "Registration failed", "error")
        return result

    def get_verification_link(self, email, domain):
        log_message(self.current_num, self.total, "Waiting for verification email...", "process")
        cookies = {
            'embx': f'[%22{email}%22]',
            'surl': f'{domain}/{email.split("@")[0]}'
        }
        headers = {'User-Agent': self.ua.random}
        
        max_attempts = 5
        for attempt in range(max_attempts):
            log_message(self.current_num, self.total, f"Attempting to get verification link (Attempt {attempt + 1}/{max_attempts})...", "process")
            response = self.make_request('GET', 'https://generator.email/inbox1/', headers=headers, cookies=cookies, timeout=120)
            
            if not response:
                log_message(self.current_num, self.total, "No response, waiting 30 seconds before retrying...", "debug")
                time.sleep(30)  # Wait for 30 seconds before retrying
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            verify_link = soup.find('a', string="Confirm Sign Up")
            
            if verify_link and 'href' in verify_link.attrs:
                log_message(self.current_num, self.total, "Verification link found", "success")
                return verify_link['href']

            log_message(self.current_num, self.total, "Verification link not found, waiting 30 seconds before retrying...", "debug")
            time.sleep(30)  # Wait for 30 seconds before retrying

        log_message(self.current_num, self.total, "Could not find verification link", "error")
        return None

    def verify_email(self, verification_url):
        log_message(self.current_num, self.total, f"Verifying email with URL: {verification_url}", "process")
        
        try:
            response = self.make_request('GET', verification_url, headers={'User-Agent': self.ua.random}, timeout=120)
            
            if not response:
                log_message(self.current_num, self.total, "Verification request failed", "error")
                return False
            
            # Log the full response text for debugging
            #log_message(self.current_num, self.total, f"Full verification response: {response.text}", "debug")
            
            # Cek respons dari API
            #log_message(self.current_num, self.total, f"Verification response: {response.status_code} - {response.text[:200]}", "debug")  # Log hanya sebagian teks untuk menghindari terlalu panjang
            
            # Periksa apakah verifikasi berhasil berdasarkan status kode dan konten HTML
            if response.status_code == 200 and "<title>Teneo Dashboard</title>" in response.text:
                log_message(self.current_num, self.total, "Email verification successful", "success")
                return True
            else:
                log_message(self.current_num, self.total, "Email verification failed", "error")
                return False
        
        except requests.exceptions.RequestException as e:
            log_message(self.current_num, self.total, f"Verification request exception: {str(e)}", "error")
            return False

    def login(self, email, password):
        log_message(self.current_num, self.total, "Attempting login...", "process")
        headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'x-api-key': 'OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjA',
            'user-agent': self.ua.random,
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/'
        }
        
        login_data = {
            "email": email,
            "password": password
        }
        
        response = self.make_request('POST', 'https://auth.teneo.pro/api/login', headers=headers, json=login_data, timeout=120)
                                   
        if not response:
            return {}
            
        result = response.json()
        
        if "access_token" in result:
            log_message(self.current_num, self.total, "Login successful", "success")
        else:
            log_message(self.current_num, self.total, "Login failed", "error")
        return result

    def link_wallet(self, access_token, email):
        log_message(self.current_num, self.total, "Generating wallet and linking...", "process")
        
        wallet = generate_ethereum_wallet()
        
        message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
        signature = create_wallet_signature(wallet, message)
        
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': f'Bearer {access_token}',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://dashboard.teneo.pro',
            'Referer': 'https://dashboard.teneo.pro/',
            'User-Agent': self.ua.random,
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
            response = self.make_request('POST', 'https://api.teneo.pro/api/users/link-wallet', headers=headers, json=link_data, timeout=60)
            
            if not response:
                return None
                
            result = response.json()

            if result.get("success"):
                log_message(self.current_num, self.total, f"{result.get('message')}: {Fore.MAGENTA}{wallet['address']}{Fore.RESET}", "success")
                return wallet
            else:
                log_message(self.current_num, self.total, f"{result.get('message', 'Unknown error')}", "error")
                return None
                
        except Exception as e:
            log_message(self.current_num, self.total, f"Error linking wallet: {str(e)}", "error")
            return None

    # Tambahan kode untuk WebSocket dan penyimpanan asinkron
    async def read_file_async(self, file_path):
        try:
            async with aiofiles.open(file_path, 'r') as f:
                return json.loads(await f.read())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    async def write_file_async(self, file_path, data):
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(data))

    async def set_local_storage(self, data):
        current_data = await self.read_file_async('localStorage.json')
        new_data = {**current_data, **data}
        await self.write_file_async('localStorage.json', new_data)

    async def connect_websocket(self, access_token):
        if self.socket:
            return
        version = "v0.2"
        url = "wss://secure.ws.teneo.pro"
        ws_url = f"{url}/websocket?accessToken={access_token}&version={version}"
        self.socket = await websockets.connect(ws_url)

        async def on_open():
            connection_time = asyncio.get_event_loop().time()
            await self.set_local_storage({'lastUpdated': connection_time})
            log_message(self.current_num, self.total, f"WebSocket connected at {connection_time}", "info")
            self.start_pinging()
            await self.start_countdown_and_points()

        async def on_message():
            async for message in self.socket:
                data = json.loads(message)
                log_message(self.current_num, self.total, f"Received message from WebSocket: {data}", "info")
                if 'pointsTotal' in data and 'pointsToday' in data:
                    last_updated = asyncio.get_event_loop().time()
                    await self.set_local_storage({
                        'lastUpdated': last_updated,
                        'pointsTotal': data['pointsTotal'],
                        'pointsToday': data['pointsToday'],
                    })
                    self.points_total = data['pointsTotal']
                    self.points_today = data['pointsToday']
                
                if 'message' in data:
                    log_message(self.current_num, self.total, f"Pesan: {data['message']}", "info")
                    if data['message'] == "Connected successfully":
                        self.stop_pinging()
                        await self.socket.close()  # Close the WebSocket connection
                        log_message(self.current_num, self.total, "WebSocket disconnected after successful connection message", "info")
                        return  # Exit the message loop

        async def on_close():
            self.socket = None
            log_message(self.current_num, self.total, "WebSocket disconnected", "info")
            self.stop_pinging()
            await self.reconnect_websocket(access_token)  # Coba untuk reconnect

        async def on_error(error):
            log_message(self.current_num, self.total, f"WebSocket error: {error}", "error")
            await self.reconnect_websocket(access_token)  # Coba untuk reconnect

        await on_open()
        try:
            await on_message()
        except Exception as e:
            await on_error(e)
        finally:
            await on_close()

    async def reconnect_websocket(self, access_token):
        log_message(self.current_num, self.total, "Attempting to reconnect...", "warning")
        await asyncio.sleep(5)
        await self.connect_websocket(access_token)  # Coba untuk reconnect

    def start_pinging(self):
        self.stop_pinging()
        self.ping_interval = asyncio.get_event_loop().call_later(10, lambda: asyncio.create_task(self.ping()))

    def stop_pinging(self):
        self.ping_interval = None

    async def ping(self):
        if self.socket and self.socket.open:  # Periksa apakah socket masih terbuka
            await self.socket.send(json.dumps({'type': 'PING'}))
            await self.set_local_storage({'lastPingDate': asyncio.get_event_loop().time()})
        self.start_pinging()

    async def update_countdown_and_points(self):
        local_storage = await self.read_file_async('localStorage.json')
        last_updated = local_storage.get('lastUpdated')
        if (last_updated):
            next_heartbeat = last_updated + 15 * 60
            now = asyncio.get_event_loop().time()
            diff = next_heartbeat - now

            if diff > 0:
                minutes = int(diff // 60)
                seconds = int(diff % 60)
                self.countdown = f"{minutes}m {seconds}s"

                max_points = 25
                time_elapsed = now - last_updated
                time_elapsed_minutes = time_elapsed / 60
                new_points = min(max_points, (time_elapsed_minutes / 15) * max_points)
                new_points = round(new_points, 2)

                if random.random() < 0.1:
                    bonus = random.uniform(0, 2)
                    new_points = min(max_points, new_points + bonus)
                    new_points = round(new_points, 2)

                self.potential_points = new_points
            else:
                self.countdown = "Calculating..."
                self.potential_points = 25
        else:
            self.countdown = "Calculating..."
            self.potential_points = 0

        await self.set_local_storage({'potentialPoints': self.potential_points, 'countdown': self.countdown})

    async def start_countdown_and_points(self):
        if self.countdown_interval:
            self.countdown_interval.cancel()
        await self.update_countdown_and_points()
        self.countdown_interval = asyncio.get_event_loop().call_later(1, lambda: asyncio.create_task(self.update_countdown_and_points()))
    
    # fungsi untuk menyimpan token ke file tokens.txt
    async def save_access_token_to_file(self, access_token):
        async with aiofiles.open('tokens.txt', 'a') as f:
            await f.write(access_token + '\n')

    async def start_running_node(self, access_token):
        await self.save_access_token_to_file(access_token)
        #print('Access token saved to tokens.txt')
        await self.start_countdown_and_points()
        await self.connect_websocket(access_token)

    def check_user_onboarded(self, access_token):
        log_message(self.current_num, self.total, "Checking account activate status...", "process")
        headers = {
            'accept': 'application/json, text/plain, */*',
            'authorization': f'Bearer {access_token}',
            'connection': 'keep-alive',
            'origin': 'https://dashboard.teneo.pro',
            'referer': 'https://dashboard.teneo.pro/',
            'user-agent': self.ua.random,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'en-GB,en;q=0.9',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site'
        }
        
        max_attempts = 5
        for attempt in range(max_attempts):
            response = self.make_request('GET', 'https://api.teneo.pro/api/users/user-onboarded', headers=headers, timeout=60)
            
            if response:
                response_data = response.json()
                if response_data.get('success') == True:
                    log_message(self.current_num, self.total, "Account Activated! But still PENDING", "success")
                    log_message(self.current_num, self.total, f"{Fore.LIGHTYELLOW_EX}IMPORTANT: Run accounts with teneo-bot until 100HB for SUCCESS referral{Fore.RESET}", "success")
                    return True
                else:
                    log_message(self.current_num, self.total, f"Response: {response_data}", "debug")
            
            log_message(self.current_num, self.total, f"User not yet activated, Please wait...", "warning")
            time.sleep(20)

        log_message(self.current_num, self.total, "Failed to verify user activation", "error")
        return False

    def create_account(self, current_num, total):
        self.current_num = current_num
        self.total = total
        
        domain, email, password = self.generate_valid_credentials() 
        if not email:
            return None, "Could not generate valid credentials after multiple attempts"

        register_response = self.register_account(email, password)
        if register_response.get("role") != "authenticated":
            return None, "Registration failed"

        verification_url = self.get_verification_link(email, domain)
        if not verification_url:
            return None, "Could not get verification link"

        if not self.verify_email(verification_url):
            return None, "Email verification failed"

        login_response = self.login(email, password)
        if "access_token" not in login_response:
            return None, "Login failed"
            
        access_token = login_response["access_token"]
        wallet = self.link_wallet(access_token, email) 
        if not wallet:
            return None, "Wallet linking failed"
        
        # Start running node with the access token from login
        asyncio.run(self.start_running_node(access_token))

        if not self.check_user_onboarded(access_token):
            return None, "Account active validation failed"

        return {
            "email": email,
            "password": password,
            "access_token": access_token,
            "wallet_private_key": wallet['private_key'],
            "wallet_address": wallet['address']
        }, "Success"

def main():
    banner = f"""
{Fore.LIGHTCYAN_EX}╔═══════════════════════════════════════════╗
║            Teneo Autoreferral             ║
║       https://github.com/im-hanzou        ║
║  Update by https://t.me/AirdropFamilyIDN  ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)    
    
    ref_code = input(f"{Fore.LIGHTYELLOW_EX}Enter referral code, example : HyPYD: {Fore.RESET}")
    count = int(input(f"{Fore.LIGHTYELLOW_EX}How many referrals?: {Fore.RESET}"))
    
    successful = 0
    
    if not os.path.exists("accounts.txt"):
        with open("accounts.txt", "w") as f:
            pass
    
    with open("accounts.txt", "a") as f:
        for i in range(count):
            print(f"{Fore.LIGHTWHITE_EX}{'-'*85}")
            log_message(i+1, count, "Starting new referral process", "debug")

            generator = TeneoAutoref(ref_code)
            account, message = generator.create_account(i+1, count)
            
            if account:
                with open("accounts.txt", "a") as f:
                    f.write(f"Email     : {account['email']}\n")
                    f.write(f"Password  : {account['password']}\n")
                    f.write(f"Privatekey: {account['wallet_private_key']}\n")
                    f.write(f"Address   : {account['wallet_address']}\n")
                    f.write(f"Points    : 51000\n")
                    f.write("-" * 85 + "\n")
                    f.flush()
                successful += 1
                log_message(i+1, count, "Account created successfully!", "debug")
                log_message(i+1, count, f"Points        : 51000", "success")
                log_message(i+1, count, f"{Fore.LIGHTRED_EX}Link Bot : https://github.com/im-hanzou/teneo-bot{Fore.RESET}", "success")
                log_message(i+1, count, f"{Fore.LIGHTRED_EX}Update by: https://t.me/AirdropFamilyIDN{Fore.RESET}", "success")
                log_message(i+1, count, f"{Fore.LIGHTRED_EX}Please ensure that all successfully referred accounts run teneo-bot{Fore.RESET}", "success")  
            else:
                log_message(i+1, count, f"Failed: {message}", "error")
    
    print(f"{Fore.MAGENTA}\n[*] Process completed!{Fore.RESET}")
    print(f"{Fore.GREEN}[*] Successfully created {successful} out of {count} accounts{Fore.RESET}")
    print(f"{Fore.MAGENTA}[*] Results saved in accounts.txt{Fore.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTYELLOW_EX}Process interrupted by user.")
