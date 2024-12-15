import discord
from discord.ext import commands
import asyncio
import socket
import struct
import re

DISCORDTOKEN = "token"
RCON_HOST = "ip"
RCON_PORT = 27301  # Default Indifferent Broccoli RCON port, change if different
RCON_PASSWORD = "password"
APPLICATION_ID = applicationid  # Add your bot's application ID here

# Admins list (Discord user IDs who are allowed to execute the command)
ADMIN_IDS = [id1, id2]  # Replace with your admin user IDs

# Discord bot setup
intents = discord.Intents.default()
intents.message_content = True  # Enable message content intent if needed
bot = commands.Bot(command_prefix='/', intents=intents, application_id=APPLICATION_ID)

# Constants for RCON packet types
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

def send_rcon_packet(sock, packet_id, packet_type, body):
    """Sends an RCON packet to the server."""
    payload = struct.pack(
        f"<ii{len(body) + 1}sB", packet_id, packet_type, body.encode("utf-8"), 0
    )
    packet = struct.pack("<i", len(payload)) + payload
    sock.sendall(packet)

def receive_rcon_packet(sock):
    """Receives an RCON packet, handling multi-packet responses."""
    try:
        raw_size = sock.recv(4)
        if not raw_size:
            return b""
        packet_size = struct.unpack("<i", raw_size)[0]
        packet_data = b""
        while len(packet_data) < packet_size:
            chunk = sock.recv(packet_size - len(packet_data))
            if not chunk:
                break
            packet_data += chunk
        all_data = raw_size + packet_data
        while len(packet_data) == packet_size:
            try:
                sock.settimeout(0.5)
                raw_size = sock.recv(4)
                if not raw_size:
                    break
                packet_size = struct.unpack("<i", raw_size)[0]
                packet_data = sock.recv(packet_size)
                all_data += raw_size + packet_data
            except socket.timeout:
                break
        return all_data
    except socket.timeout:
        return b""
    except Exception as e:
        return b""

def decode_rcon_response(data):
    """Decodes the RCON response to extract the payload."""
    try:
        responses = []
        while data:
            if len(data) < 12:
                break
            packet_size = struct.unpack("<i", data[:4])[0]
            if len(data) < 4 + packet_size:
                break
            packet_id, response_type = struct.unpack("<ii", data[4:12])
            payload = data[12:4 + packet_size - 2].decode("utf-8", errors="ignore").strip()
            responses.append(payload)
            data = data[4 + packet_size:]
        return "\n".join(responses)
    except Exception as e:
        return ""

async def get_player_list():
    """Fetches the list of players from the RCON server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            sock.connect((RCON_HOST, RCON_PORT))
            
            # Authenticate
            send_rcon_packet(sock, 1, SERVERDATA_AUTH, RCON_PASSWORD)
            auth_response = receive_rcon_packet(sock)
            if not auth_response:
                return "Authentication failed", []
            auth_status = struct.unpack("<i", auth_response[4:8])[0]
            if auth_status == -1:
                return "Authentication failed: Invalid password", []

            # Send 'players' command
            send_rcon_packet(sock, 2, SERVERDATA_EXECCOMMAND, "players")
            response = receive_rcon_packet(sock)
            if not response:
                return "No response to 'players' command", []

            # Decode the response
            response_text = decode_rcon_response(response)

            # Extract the player count
            match = re.search(r"Players connected \((\d+)\):", response_text)
            if match:
                player_count = match.group(1)
                player_list = response_text.splitlines()[1:]  # List of players
                return player_count, player_list
            else:
                return "No players connected", []

    except Exception as e:
        return "Error fetching player list", []

async def send_rcon_command_to_pz(command):
    """Send a command to Project Zomboid server via RCON."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            sock.connect((RCON_HOST, RCON_PORT))
            
            # Authenticate
            send_rcon_packet(sock, 1, SERVERDATA_AUTH, RCON_PASSWORD)
            auth_response = receive_rcon_packet(sock)
            if not auth_response:
                return "Authentication failed"
            auth_status = struct.unpack("<i", auth_response[4:8])[0]
            if auth_status == -1:
                return "Authentication failed: Invalid password"
            
            # Send command
            send_rcon_packet(sock, 2, SERVERDATA_EXECCOMMAND, command)
            response = receive_rcon_packet(sock)
            if not response:
                return "No response to the command"
            
            # Decode response
            response_text = decode_rcon_response(response)
            return response_text
    except Exception as e:
        return f"Error sending RCON command: {str(e)}"

@bot.tree.command(name='players')
async def players(interaction: discord.Interaction):
    """Fetches the list of players currently connected to the Project Zomboid server."""
    print("Fetching player list...")
    player_count, player_list = await get_player_list()
    
    # Format player list
    player_list_message = "\n".join(player_list) if player_list else "No players connected"
    await interaction.response.send_message(f"**Players Connected:  ({player_count})**\n{player_list_message}")

@bot.tree.command(name='execute')
async def execute(interaction: discord.Interaction, command: str):
    """Executes a command on the Project Zomboid server, restricted to admins."""
    
    # Check if the user is an admin
    if interaction.user.id not in ADMIN_IDS:
        await interaction.response.send_message("You do not have permission to execute this command.", ephemeral=True)
        return
    
    # Process the full command string
    full_command = command.strip()
    
    print(f"Executing command: {full_command}")
    response = await send_rcon_command_to_pz(full_command)
    
    # Ensure the response doesn't exceed Discord's 2000 character limit
    if len(response) > 2000:
        response = response[:2000] + "\n... (truncated)"
    
    # Send the response back to Discord
    await interaction.response.send_message(f"**Command Execution Result:**\n```\n{response}\n```")

@bot.event
async def on_ready():
    print(f"{bot.user} has connected to Discord!")
    await bot.tree.sync()  # Sync globally (or use a specific guild if needed)
    print("Slash commands synced.")
    
    # Start periodic status updates
    asyncio.create_task(update_bot_status())

async def update_bot_status():
    """Periodically updates the Discord bot status with the player count."""
    await bot.wait_until_ready()
    while not bot.is_closed():
        print("Updating bot status...")
        player_count, _ = await get_player_list()
        status = f"Players Online:  ({player_count})" if player_count != "No players connected" else "No players"
        print(f"Setting bot status to: {status}")
        await bot.change_presence(activity=discord.Game(name=status))
        await asyncio.sleep(10)

bot.run(DISCORDTOKEN)
