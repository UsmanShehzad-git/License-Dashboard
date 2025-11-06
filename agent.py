#!/usr/bin/python3

import subprocess
import re
import sys
import sqlite3
import json
from datetime import datetime
import os
import grp

DB_PATH = "/var/ossec/active-response/bin/network_scan.db"
LOG_FILE = "/var/ossec/logs/active-responses.log"
GROUP_NAME = "wazuh"

def update_db_folder_permissions():
    db_folder = os.path.dirname(DB_PATH)
    try:
        gid = grp.getgrnam(GROUP_NAME).gr_gid
        os.chown(db_folder, 0, gid)
    except OSError as e:
        write_debug_log(f"Error changing DB Folder ownership: {e}")
    try:
        os.chmod(db_folder, 0o750)
    except OSError as e:
        write_debug_log(f"Error changing DB Folder permissions: {e}")

def write_debug_log(message):
    """Write debug information to the log file."""
    timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")

def initialize_database():
    """Ensure the database and the scan_results table exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            ip TEXT PRIMARY KEY,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            vendor TEXT
        )
    """)

    conn.commit()
    conn.close()
    update_db_folder_permissions()
    write_debug_log("Database initialized with table scan_results.")


def insert_ip_status(ip, status,vendor):
    """Insert or update the ip status in the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # First check if ip exists
    cursor.execute('SELECT created_at FROM scan_results WHERE ip = ?', (ip,))
    result = cursor.fetchone()

    if result:
        # ip exists, use existing created_at
        created_at = result[0]
    else:
        # New ip, use current timestamp for created_at
        created_at = now

    cursor.execute('''INSERT OR REPLACE INTO scan_results(ip, created_at, updated_at, status,vendor)
                      VALUES (?, ?, ?, ?,?)''', (ip, created_at, now, status,vendor))

    conn.commit()
    conn.close()
    write_debug_log(f"Database updated: ip={ip}, Status={status}")

def run_netdiscover(ip_range, timeout=40):
    """Run netdiscover in the specified ip range with a timeout."""
    try:
        process = subprocess.Popen(
            ["sudo", "netdiscover", "-r", ip_range, "-P", "-N"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        write_debug_log(f"Running netdiscover for range: {ip_range}")

        stdout, stderr = process.communicate(timeout=timeout)

        if stderr:
            write_debug_log(f"Netdiscover stderr: {stderr.strip()}")

        if process.returncode != 0:
            write_debug_log(f"Netdiscover exited with code {process.returncode}")

        return stdout.splitlines() if stdout else []
    except subprocess.TimeoutExpired:
        process.kill()
        write_debug_log(f"Netdiscover timed out after {timeout} seconds.")
        return []
    except Exception as e:
        write_debug_log(f"Error running netdiscover: {e}")
        return []

def get_os_vendor(ip):
    try:
        result = subprocess.run(
            ["nmap", "-O", "-T4", "-Pn", ip],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.lower()
        write_debug_log(f"Nmap output for OS detection: {output}")  

        if "windows" in output:
            return "Windows"
        elif "linux" in output:
            return "Linux"
        elif "apple" in output or "mac os" in output or "macos" in output:
            return "MacOS"
        elif "freebsd" in output:
            return "FreeBSD"
        elif "openbsd" in output:
            return "OpenBSD"
        elif "android" in output:
            return "Android"
        else:
            return "Unknown"
    except Exception as e:
        write_debug_log(f"Error running nmap for OS detection: {e}")
        return "Unknown"
    
def check_ip_in_network(target_ip, ip_range):
    """Check if the target ip exists in the specified network range."""
    output_lines = run_netdiscover(ip_range)
    if not output_lines:
        write_debug_log("No output from netdiscover. Exiting ip check.")
        return False

    ip_pattern = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    discovered_ips = []

    for line in output_lines:
        write_debug_log(f"Processing line: {line}")
        match = ip_pattern.match(line)
        if match:
            ip = match.group(1)
            discovered_ips.append(ip)
            write_debug_log(f"Matched ip: {ip}")

    is_present = target_ip in discovered_ips
    write_debug_log(f"Netdiscover Discovered IPs: {discovered_ips}")

    if is_present:
        print(f"ip {target_ip} is recognized and already exists on the network.")
        vendor = get_os_vendor(target_ip)
        insert_ip_status(target_ip, 'Found',vendor)
    else:
        print(f"ip {target_ip} is not recognized! Triggering active response.")
        vendor = get_os_vendor(target_ip)
        insert_ip_status(target_ip, 'Not Found',vendor)

    return None

def read_alert_from_stdin():
    """Read the alert from stdin and parse the target ip."""
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_log(f"Received alert: {input_str}")

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_log('Decoding JSON has failed, invalid input format')
        return None

    write_debug_log(f"Parsed JSON: {json.dumps(data, indent=4)}")

    target_ip = data.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip")
    if not target_ip:
        write_debug_log('No source ip (srcip) found in the alert')
        return None

    return target_ip

def process_ip_list_from_user(ip_list):
    """Process each ip to check its presence in the network."""
    if not ip_list:
        print("No valid IPs provided. Exiting...")
        write_debug_log("No valid IPs provided by the user.")
        return

    for ip in ip_list:
        write_debug_log(f"Processing user-provided ip: {ip}")
        try:
            network_range = f"{ip.rsplit('.', 1)[0]}.0/24"
            write_debug_log(f"Determined network range: {network_range}")
            check_ip_in_network(ip, network_range)
        except Exception as e:
            write_debug_log(f"Error processing ip {ip}: {e}")

    print("Processing completed. Check logs for more details.")

def main():
    """Main function to handle ip discovery and processing."""
    initialize_database()

    print("ip Discovery Tool")

    # Check if running as active response (stdin has data)
    if not sys.stdin.isatty():
        target_ip = read_alert_from_stdin()
        if not target_ip:
            write_debug_log("No target ip found in stdin. Exiting...")
            sys.exit(1)

        network_range = f"{target_ip.rsplit('.', 1)[0]}.0/24"
        write_debug_log(f"Initiating network check for ip: {target_ip}")
        check_ip_in_network(target_ip, network_range)
        return

    # Manual mode - get input from user
    user_input = input("Enter a comma-separated list of IPs: ").strip()
    ip_list = [ip.strip() for ip in user_input.split(",") if ip.strip()]

    if not ip_list:
        print("No valid IPs provided. Exiting...")
        write_debug_log("No valid IPs provided by the user.")
        return

    process_ip_list_from_user(ip_list)

if __name__ == "__main__":
    main()