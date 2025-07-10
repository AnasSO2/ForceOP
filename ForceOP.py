import websocket
import threading
import time
import uuid
import struct
import ssl
import sys
import os
from datetime import datetime
from colorama import Fore, Style, init
import nbtlib
from nbtlib import tag
import json

init(autoreset=True)

LOG_FILE = "forceop_log.txt"
SETTINGS_FILE = "forceop_settings.json"
SESSION_LOG = "session_log.json"

def log(msg):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def print_color(msg, color):
    print(color + msg + Style.RESET_ALL)
    log(msg)

def generate_advanced_uuid(username):
    import hashlib
    ns = uuid.UUID('12345678-1234-5678-1234-567812345678')
    name = username.encode('utf-8')
    hash_bytes = hashlib.md5(ns.bytes + name).digest()
    generated_uuid = uuid.UUID(bytes=hash_bytes)
    return str(generated_uuid)

def encode_string(s):
    encoded = s.encode('utf-8')
    length = len(encoded)
    return struct.pack('>H', length) + encoded

def pack_packet(packet_id, payload_bytes):
    length = len(payload_bytes) + 1
    return struct.pack('>I', length) + struct.pack('B', packet_id) + payload_bytes

def create_login_nbt(username, uuid_str):
    compound = nbtlib.Compound({
        'ClientRandomId': tag.Long(int(uuid.uuid4().int >> 64)),
        'ProtocolVersion': tag.Int(1),
        'Username': tag.String(username),
        'Uuid': tag.String(uuid_str),
        'ClientId': tag.String('ForceOP-Python-Tool-Advanced'),
        'SkinData': tag.ByteArray(b''),
        'SkinId': tag.String('Standard_Custom'),
        'ThirdPartyName': tag.String(''),
        'ThirdPartyId': tag.String(''),
        'ThirdPartyProof': tag.String('')
    })
    return compound.save(buffer=None)

def create_command_packet(command):
    return encode_string(command)

class ForceOPClient:
    def __init__(self, ip, port, username, use_ssl, commands, delay=2, reconnect=True, resume=False):
        self.ip = ip
        self.port = port
        self.username = username
        self.use_ssl = use_ssl
        self.commands = commands
        self.delay = delay
        self.reconnect = reconnect
        self.resume = resume
        self.ws = None
        self.uuid = generate_advanced_uuid(username)
        self.connected = False
        self.stop_flag = False
        self.sent_commands_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.last_command_index = -1
        self.session_start_time = datetime.now()
        self.session_commands_log = []

    def on_message(self, ws, message):
        print_color(f"[Server]: {message}", Fore.CYAN)
        lowered = message.lower()
        success_keywords = ['success', 'op granted', 'تم', 'نجح', 'done', 'enabled', 'gave']
        fail_keywords = ['fail', 'error', 'خطأ', 'failed', 'denied', 'not allowed']

        if any(word in lowered for word in success_keywords):
            print_color("[+] Command execution succeeded.", Fore.GREEN)
            self.success_count += 1
            self.session_commands_log.append({'command': self.commands[self.sent_commands_count-1], 'result': 'success'})
            log("[+] Command execution succeeded.")
        elif any(word in lowered for word in fail_keywords):
            print_color("[-] Command execution failed.", Fore.RED)
            self.fail_count += 1
            self.session_commands_log.append({'command': self.commands[self.sent_commands_count-1], 'result': 'fail'})
            log("[-] Command execution failed.")
        else:
            # رسالة عامة
            self.session_commands_log.append({'command': self.commands[self.sent_commands_count-1], 'result': 'unknown'})

    def on_error(self, ws, error):
        print_color(f"[Error]: {error}", Fore.RED)

    def on_close(self, ws, close_status_code, close_msg):
        self.connected = False
        print_color(f"[Disconnected from server]", Fore.RED)
        if self.reconnect and not self.stop_flag:
            print_color("[!] Trying to reconnect in 5 seconds...", Fore.YELLOW)
            time.sleep(5)
            self.connect()

    def send_packet(self, packet_id, payload):
        packet = pack_packet(packet_id, payload)
        self.ws.send(packet, opcode=websocket.ABNF.OPCODE_BINARY)

    def send_login(self):
        print_color(f"[+] Logging in with username: {self.username} and UUID: {self.uuid}", Fore.YELLOW)
        login_nbt = create_login_nbt(self.username, self.uuid)
        self.send_packet(0x01, login_nbt)
        print_color("[+] Login packet sent.", Fore.GREEN)

    def send_commands(self):
        start_index = 0
        if self.resume and self.last_command_index >= 0:
            start_index = self.last_command_index + 1
            print_color(f"[*] Resuming from command index {start_index}", Fore.YELLOW)

        for idx in range(start_index, len(self.commands)):
            if self.stop_flag:
                break
            cmd = self.commands[idx]
            print_color(f"[{idx+1}/{len(self.commands)}] Sending command: {cmd}", Fore.YELLOW)
            cmd_payload = create_command_packet(cmd)
            self.send_packet(0x02, cmd_payload)
            self.sent_commands_count += 1
            self.last_command_index = idx
            time.sleep(self.delay)
        print_color("[*] All commands sent or stopped.", Fore.MAGENTA)
        self.print_session_summary()

    def print_session_summary(self):
        duration = datetime.now() - self.session_start_time
        print_color("\n════════ SESSION SUMMARY ════════", Fore.CYAN)
        print_color(f"User: {self.username}", Fore.CYAN)
        print_color(f"Server: {self.ip}:{self.port}", Fore.CYAN)
        print_color(f"Commands sent: {self.sent_commands_count}", Fore.CYAN)
        print_color(f"Successful commands: {self.success_count}", Fore.GREEN)
        print_color(f"Failed commands: {self.fail_count}", Fore.RED)
        print_color(f"Duration: {duration}", Fore.CYAN)
        print_color("══════════════════════════════════\n", Fore.CYAN)
        # سجل الجلسة في ملف
        self.save_session_log()

    def save_session_log(self):
        session_data = {
            'username': self.username,
            'server_ip': self.ip,
            'server_port': self.port,
            'commands': self.commands,
            'sent_commands': self.sent_commands_count,
            'success_count': self.success_count,
            'fail_count': self.fail_count,
            'duration_seconds': (datetime.now() - self.session_start_time).total_seconds(),
            'command_results': self.session_commands_log,
            'timestamp': self.session_start_time.strftime('%Y-%m-%d %H:%M:%S')
        }
        # قراءة سابق
        sessions = []
        if os.path.exists(SESSION_LOG):
            with open(SESSION_LOG, "r", encoding="utf-8") as f:
                try:
                    sessions = json.load(f)
                except Exception:
                    sessions = []
        sessions.append(session_data)
        with open(SESSION_LOG, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=4)

    def on_open(self, ws):
        self.connected = True
        print_color(f"[Connected to {self.ip}:{self.port}]", Fore.GREEN)
        self.send_login()
        threading.Thread(target=self.send_commands, daemon=True).start()

    def connect(self):
        schema = "wss" if self.use_ssl else "ws"
        ws_url = f"{schema}://{self.ip}:{self.port}"
        sslopt = {"cert_reqs": ssl.CERT_NONE} if self.use_ssl else None

        self.ws = websocket.WebSocketApp(
            ws_url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )

        if self.use_ssl:
            self.ws.run_forever(sslopt=sslopt)
        else:
            self.ws.run_forever()

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def save_settings(ip, port, username, use_ssl, commands, delay, reconnect, resume):
    settings = {
        "ip": ip,
        "port": port,
        "username": username,
        "use_ssl": use_ssl,
        "commands": commands,
        "delay": delay,
        "reconnect": reconnect,
        "resume": resume
    }
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def select_option(prompt, options):
    while True:
        print_color(prompt, Fore.CYAN)
        for i, option in enumerate(options, 1):
            print_color(f"{i}. {option}", Fore.YELLOW)
        choice = input(">> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice)
        else:
            print_color("[!] Invalid choice, try again.", Fore.RED)

def main():
    clear_console()
    print_color("═══════════════════════════════════════", Fore.RED)
    print_color("          ☠ FORCEOP TOOL ☠", Fore.RED)
    print_color("        Coded by AnasSO ⚡", Fore.RED)
    print_color("═══════════════════════════════════════\n", Fore.RED)

    settings = load_settings()
    if settings:
        print_color("[*] Loaded saved settings.", Fore.GREEN)
        ip = settings.get("ip")
        port = settings.get("port")
        username = settings.get("username")
        use_ssl = settings.get("use_ssl")
        commands = settings.get("commands")
        delay = settings.get("delay", 2)
        reconnect = settings.get("reconnect", True)
        resume = settings.get("resume", False)
        use_saved = select_option("Use saved settings?", ["Yes", "No"])
        if use_saved == 2:
            settings = None

    if not settings:
        username = input(Fore.CYAN + "Enter your in-game name:\n>> ")
        ip = input(Fore.CYAN + "Enter server IP:\n>> ")
        port = input(Fore.CYAN + "Enter server port:\n>> ")
        ssl_input = input(Fore.CYAN + "Use SSL/WSS connection? (yes/no):\n>> ").strip().lower()
        use_ssl = ssl_input in ['yes', 'y']
        cmds_input = input(Fore.CYAN + "Enter commands to send (separate with comma):\n>> ")
        commands = [cmd.strip() for cmd in cmds_input.split(',') if cmd.strip()]
        delay = input(Fore.CYAN + "Delay between commands in seconds (default 2):\n>> ").strip()
        try:
            delay = float(delay)
        except:
            delay = 2.0
        reconnect_opt = select_option("Enable auto reconnect?", ["Yes", "No"])
        reconnect = reconnect_opt == 1
        resume_opt = select_option("Enable resume from last sent command?", ["Yes", "No"])
        resume = resume_opt == 1
        try:
            port = int(port)
        except ValueError:
            print_color("Invalid port number.", Fore.RED)
            sys.exit(1)
        save_settings(ip, port, username, use_ssl, commands, delay, reconnect, resume)

    client = ForceOPClient(ip, port, username, use_ssl, commands, delay, reconnect, resume)
    try:
        client.connect()
    except KeyboardInterrupt:
        print_color("\n[!] User interrupted. Exiting...", Fore.RED)
        client.stop_flag = True
        sys.exit(0)

if __name__ == "__main__":
    main()
