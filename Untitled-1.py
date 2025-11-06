"""
Advanced WiFi Security & Network Analysis Tool v3.0
Professional-grade network testing and analysis suite for Windows
⚠️ For authorized security testing and educational purposes only
"""

import os
import subprocess
import time
import sys
import re
import random
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from collections import defaultdict
import ctypes
from dataclasses import dataclass, asdict
from enum import Enum

os.system("")  # Enable ANSI colors on Windows

# ==================== CONFIGURATION & CONSTANTS ====================
class Config:
    VERSION = "3.0"
    LOG_FILE = "wifi_security_tool.log"
    CONFIG_FILE = "wifi_tool_config.json"
    SCAN_HISTORY_FILE = "scan_history.json"
    MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
    COMMAND_TIMEOUT = 30

class Colors:
    """ANSI color codes with styles"""
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

class SecurityLevel(Enum):
    """Network security classification"""
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2-Personal"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    WPA3 = "WPA3"
    UNKNOWN = "Unknown"

# ==================== DATA CLASSES ====================
@dataclass
class WiFiNetwork:
    """WiFi network information"""
    ssid: str
    signal: int = 0
    channel: int = 0
    security: str = ""
    bssid: Optional[str] = None
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    radio_type: Optional[str] = None

    def get_security_level(self) -> SecurityLevel:
        """Determine security level"""
        if not self.security or "Open" in self.security:
            return SecurityLevel.OPEN
        elif "WPA3" in self.security:
            return SecurityLevel.WPA3
        elif "WPA2" in self.security:
            if "Enterprise" in self.security:
                return SecurityLevel.WPA2_ENTERPRISE
            return SecurityLevel.WPA2
        elif "WPA" in self.security:
            return SecurityLevel.WPA
        elif "WEP" in self.security:
            return SecurityLevel.WEP
        return SecurityLevel.UNKNOWN

@dataclass
class NetworkDevice:
    """Connected network device information"""
    ip: str
    mac: str
    type: str
    interface: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

@dataclass
class InterfaceInfo:
    """Network interface information"""
    name: str
    status: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    gateway: Optional[str] = None
    dns: Optional[List[str]] = None
    driver: Optional[str] = None
    speed: Optional[str] = None

# ==================== UTILITY CLASSES ====================
class Logger:
    """Advanced logging system with rotation"""

    @staticmethod
    def _rotate_log():
        """Rotate log file if too large"""
        if os.path.exists(Config.LOG_FILE):
            if os.path.getsize(Config.LOG_FILE) > Config.MAX_LOG_SIZE:
                backup = f"{Config.LOG_FILE}.{int(time.time())}"
                os.rename(Config.LOG_FILE, backup)
                Logger.log("Log rotated to " + backup, "SYSTEM")

    @staticmethod
    def log(message: str, level: str = "INFO", console: bool = False):
        """Enhanced logging with levels and optional console output"""
        Logger._rotate_log()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{level:8}] {message}\n"

        try:
            with open(Config.LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Logging error: {e}")

        if console:
            print(log_entry.strip())

    @staticmethod
    def get_recent_logs(lines: int = 50) -> List[str]:
        """Get recent log entries"""
        try:
            with open(Config.LOG_FILE, "r", encoding="utf-8") as f:
                return f.readlines()[-lines:]
        except:
            return []

class Printer:
    """Formatted console output"""

    @staticmethod
    def success(msg: str):
        print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}[✓] {msg}{Colors.RESET}")
        Logger.log(msg, "SUCCESS")

    @staticmethod
    def error(msg: str):
        print(f"{Colors.BRIGHT_RED}{Colors.BOLD}[✗] {msg}{Colors.RESET}")
        Logger.log(msg, "ERROR")

    @staticmethod
    def info(msg: str):
        print(f"{Colors.BRIGHT_CYAN}[ℹ] {msg}{Colors.RESET}")
        Logger.log(msg, "INFO")

    @staticmethod
    def warning(msg: str):
        print(f"{Colors.BRIGHT_YELLOW}[⚠] {msg}{Colors.RESET}")
        Logger.log(msg, "WARNING")

    @staticmethod
    def critical(msg: str):
        print(f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}[‼] {msg}{Colors.RESET}")
        Logger.log(msg, "CRITICAL")

    @staticmethod
    def section(title: str):
        """Print section header"""
        width = 70
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*width}")
        print(f"{title.center(width)}")
        print(f"{'='*width}{Colors.RESET}\n")

    @staticmethod
    def progress_bar(current: int, total: int, prefix: str = "", length: int = 40):
        """Display progress bar"""
        percent = current / total if total > 0 else 0
        filled = int(length * percent)
        bar = "█" * filled + "░" * (length - filled)
        print(f"\r{prefix} |{bar}| {percent*100:.1f}% ({current}/{total})", end="", flush=True)

class SystemUtils:
    """System utility functions"""

    @staticmethod
    def is_admin() -> bool:
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def clear_screen():
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get system information"""
        info = {}
        try:
            info['OS'] = os.name
            info['Python'] = sys.version.split()[0]
            info['User'] = os.getenv('USERNAME', 'Unknown')
            info['Computer'] = os.getenv('COMPUTERNAME', 'Unknown')
        except:
            pass
        return info

    @staticmethod
    def run_command(cmd: str, capture: bool = True, timeout: int = Config.COMMAND_TIMEOUT) -> Optional[str]:
        """Execute shell command with error handling"""
        try:
            if capture:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding='utf-8',
                    errors='ignore'
                )
                return result.stdout if result.returncode == 0 else None
            else:
                result = subprocess.run(cmd, shell=True, timeout=timeout)
                return "Success" if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            Logger.log(f"Command timeout: {cmd}", "ERROR")
            return None
        except Exception as e:
            Logger.log(f"Command error: {cmd} - {e}", "ERROR")
            return None

class ConfigManager:
    """Configuration management"""

    @staticmethod
    def load() -> Dict[str, Any]:
        """Load configuration"""
        if os.path.exists(Config.CONFIG_FILE):
            try:
                with open(Config.CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                Logger.log(f"Config load error: {e}", "ERROR")
        return {}

    @staticmethod
    def save(config: Dict[str, Any]):
        """Save configuration"""
        try:
            with open(Config.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            Logger.log(f"Config save error: {e}", "ERROR")

    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        """Get config value"""
        config = ConfigManager.load()
        return config.get(key, default)

    @staticmethod
    def set(key: str, value: Any):
        """Set config value"""
        config = ConfigManager.load()
        config[key] = value
        ConfigManager.save(config)

class Validator:
    """Input validation"""

    @staticmethod
    def mac_address(mac: str) -> bool:
        """Validate MAC address format"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
        return bool(re.match(pattern, mac))

    @staticmethod
    def ip_address(ip: str) -> bool:
        """Validate IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

    @staticmethod
    def ssid(ssid: str) -> bool:
        """Validate SSID (1-32 characters)"""
        return 1 <= len(ssid) <= 32

    @staticmethod
    def password(password: str, min_length: int = 8) -> bool:
        """Validate password strength"""
        return len(password) >= min_length

class MACGenerator:
    """MAC address generation and manipulation"""

    VENDOR_OUIS = {
        'Apple': ['00:03:93', '00:05:02', '00:0A:27', '00:0D:93'],
        'Cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63'],
        'Dell': ['00:06:5B', '00:08:74', '00:0B:DB', '00:0D:56'],
        'HP': ['00:01:E6', '00:01:E7', '00:02:A5', '00:04:EA'],
        'Intel': ['00:02:B3', '00:03:47', '00:04:23', '00:07:E9'],
        'Samsung': ['00:00:F0', '00:07:AB', '00:09:18', '00:0D:AE'],
        'Microsoft': ['00:03:FF', '00:0D:3A', '00:12:5A', '00:15:5D'],
    }

    @staticmethod
    def random_mac(locally_administered: bool = True) -> str:
        """Generate random MAC address"""
        if locally_administered:
            first_octet = 0x02
        else:
            first_octet = random.randint(0x00, 0xFF) & 0xFE

        mac = [first_octet] + [random.randint(0x00, 0xFF) for _ in range(5)]
        return ':'.join(f'{octet:02x}' for octet in mac)

    @staticmethod
    def vendor_mac(vendor: str) -> Optional[str]:
        """Generate MAC with specific vendor OUI"""
        ouis = MACGenerator.VENDOR_OUIS.get(vendor, [])
        if not ouis:
            return None

        oui = random.choice(ouis).replace(':', '')
        suffix = ''.join(f'{random.randint(0x00, 0xFF):02x}' for _ in range(3))
        mac = oui + suffix
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def get_vendors() -> List[str]:
        """Get list of available vendors"""
        return list(MACGenerator.VENDOR_OUIS.keys())

# ==================== NETWORK OPERATIONS ====================
class NetworkInterface:
    """Network interface management"""

    @staticmethod
    def list_all() -> List[InterfaceInfo]:
        """List all network interfaces with details"""
        interfaces = []
        output = SystemUtils.run_command('netsh interface show interface')

        if not output:
            return interfaces

        for line in output.split('\n'):
            if 'Connected' in line or 'Disconnected' in line:
                parts = line.split()
                if len(parts) >= 4:
                    status = parts[1]
                    name = ' '.join(parts[3:])
                    mac = NetworkInterface.get_mac(name)
                    ip_info = NetworkInterface.get_ip_info(name)

                    interface = InterfaceInfo(
                        name=name,
                        status=status,
                        mac=mac,
                        ip=ip_info.get('ip'),
                        gateway=ip_info.get('gateway'),
                        dns=ip_info.get('dns')
                    )
                    interfaces.append(interface)

        return interfaces

    @staticmethod
    def get_mac(interface: str) -> Optional[str]:
        """Get MAC address of interface"""
        output = SystemUtils.run_command('getmac /v /fo csv')
        if output:
            for line in output.split('\n'):
                if interface in line:
                    match = re.search(r'([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}', line)
                    if match:
                        return match.group(0).replace('-', ':')
        return None

    @staticmethod
    def get_ip_info(interface: str) -> Dict[str, Any]:
        """Get IP configuration for interface"""
        info = {}
        output = SystemUtils.run_command(f'netsh interface ip show config name="{interface}"')

        if output:
            ip_match = re.search(r'IP Address:\s+(\d+\.\d+\.\d+\.\d+)', output)
            if ip_match:
                info['ip'] = ip_match.group(1)

            gw_match = re.search(r'Default Gateway:\s+(\d+\.\d+\.\d+\.\d+)', output)
            if gw_match:
                info['gateway'] = gw_match.group(1)

            dns_servers = re.findall(r'DNS Servers:\s+(\d+\.\d+\.\d+\.\d+)', output)
            if dns_servers:
                info['dns'] = dns_servers

        return info

    @staticmethod
    def restart(interface: str) -> bool:
        """Restart network interface"""
        Printer.info(f"Restarting interface: {interface}")

        if not SystemUtils.run_command(f'netsh interface set interface name="{interface}" admin=disabled', capture=False):
            return False

        time.sleep(2)

        if not SystemUtils.run_command(f'netsh interface set interface name="{interface}" admin=enabled', capture=False):
            return False

        time.sleep(2)
        Printer.success(f"Interface {interface} restarted")
        return True

    @staticmethod
    def enable(interface: str) -> bool:
        """Enable interface"""
        return bool(SystemUtils.run_command(f'netsh interface set interface name="{interface}" admin=enabled', capture=False))

    @staticmethod
    def disable(interface: str) -> bool:
        """Disable interface"""
        return bool(SystemUtils.run_command(f'netsh interface set interface name="{interface}" admin=disabled', capture=False))

class WiFiScanner:
    """WiFi network scanning and analysis"""

    @staticmethod
    def scan() -> List[WiFiNetwork]:
        """Scan for WiFi networks"""
        Printer.info("Scanning WiFi networks...")
        networks = []

        output = SystemUtils.run_command('netsh wlan show networks mode=bssid')
        if not output:
            Printer.error("Failed to scan networks")
            return networks

        current_network = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('SSID'):
                if current_network and current_network.get('ssid'):
                    networks.append(WiFiNetwork(**current_network))
                match = re.search(r'SSID \d+ : (.+)', line)
                if match:
                    current_network = {'ssid': match.group(1).strip()}

            elif 'Signal' in line:
                match = re.search(r'(\d+)%', line)
                if match:
                    current_network['signal'] = int(match.group(1))

            elif 'Authentication' in line:
                current_network['security'] = line.split(':', 1)[1].strip()

            elif 'Encryption' in line:
                current_network['encryption'] = line.split(':', 1)[1].strip()

            elif 'BSSID' in line:
                match = re.search(r'BSSID \d+ : (.+)', line)
                if match:
                    current_network['bssid'] = match.group(1).strip()

            elif 'Channel' in line:
                match = re.search(r'Channel\s+:\s+(\d+)', line)
                if match:
                    current_network['channel'] = int(match.group(1))

            elif 'Radio type' in line:
                current_network['radio_type'] = line.split(':', 1)[1].strip()

        if current_network and current_network.get('ssid'):
            networks.append(WiFiNetwork(**current_network))

        Printer.success(f"Found {len(networks)} networks")
        return networks

    @staticmethod
    def display_networks(networks: List[WiFiNetwork]):
        """Display networks in formatted table"""
        if not networks:
            Printer.warning("No networks found")
            return

        networks.sort(key=lambda x: x.signal, reverse=True)
        Printer.section("WiFi Networks")

        col_widths = [32, 10, 10, 25, 20]
        headers = ["SSID", "Signal", "Channel", "Security", "BSSID"]
        
        header_line = " │ ".join(f"{headers[i]:<{col_widths[i]-2}}" for i in range(len(headers)))
        separator = "─┼─".join("─" * (w-2) for w in col_widths)

        print(f"{Colors.CYAN}{Colors.BOLD}{header_line}{Colors.RESET}")
        print(f"{Colors.CYAN}{separator}{Colors.RESET}")

        for net in networks:
            security = net.security or "Unknown"
            if "Open" in security:
                security_colored = f"{Colors.RED}{security}{Colors.RESET}"
            elif "WPA3" in security:
                security_colored = f"{Colors.GREEN}{security}{Colors.RESET}"
            elif "WPA2" in security:
                security_colored = f"{Colors.YELLOW}{security}{Colors.RESET}"
            else:
                security_colored = security

            signal = net.signal
            if signal >= 70:
                signal_str = f"{Colors.GREEN}{signal}%{Colors.RESET}"
            elif signal >= 50:
                signal_str = f"{Colors.YELLOW}{signal}%{Colors.RESET}"
            else:
                signal_str = f"{Colors.RED}{signal}%{Colors.RESET}"

            row = [
                net.ssid[:30],
                signal_str,
                str(net.channel) if net.channel else "?",
                security_colored,
                net.bssid[:17] if net.bssid else "N/A"
            ]
            
            row_line = " │ ".join(f"{str(row[i]):<{col_widths[i]+8}}" for i in range(len(row)))
            print(row_line)

        print()

    @staticmethod
    def analyze_networks(networks: List[WiFiNetwork]) -> Dict[str, Any]:
        """Analyze network security"""
        analysis = {
            'total': len(networks),
            'open': 0,
            'wep': 0,
            'wpa': 0,
            'wpa2': 0,
            'wpa3': 0,
            'channels': defaultdict(int),
            'weak_security': []
        }

        for net in networks:
            level = net.get_security_level()

            if level == SecurityLevel.OPEN:
                analysis['open'] += 1
                analysis['weak_security'].append((net.ssid, "Open network"))
            elif level == SecurityLevel.WEP:
                analysis['wep'] += 1
                analysis['weak_security'].append((net.ssid, "WEP (deprecated)"))
            elif level == SecurityLevel.WPA:
                analysis['wpa'] += 1
            elif level == SecurityLevel.WPA2:
                analysis['wpa2'] += 1
            elif level == SecurityLevel.WPA3:
                analysis['wpa3'] += 1

            if net.channel:
                analysis['channels'][net.channel] += 1

        return analysis

    @staticmethod
    def display_analysis(analysis: Dict[str, Any]):
        """Display network analysis"""
        Printer.section("Security Analysis")

        print(f"Total networks: {Colors.BOLD}{analysis['total']}{Colors.RESET}")
        print(f"  {Colors.RED}Open:{Colors.RESET} {analysis['open']}")
        print(f"  {Colors.RED}WEP:{Colors.RESET} {analysis['wep']}")
        print(f"  {Colors.YELLOW}WPA:{Colors.RESET} {analysis['wpa']}")
        print(f"  {Colors.GREEN}WPA2:{Colors.RESET} {analysis['wpa2']}")
        print(f"  {Colors.BRIGHT_GREEN}WPA3:{Colors.RESET} {analysis['wpa3']}")

        if analysis['weak_security']:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠ Networks with weak security:{Colors.RESET}")
            for ssid, reason in analysis['weak_security']:
                print(f"  • {ssid}: {reason}")

        if analysis['channels']:
            print(f"\n{Colors.CYAN}Channel distribution:{Colors.RESET}")
            sorted_channels = sorted(analysis['channels'].items(), key=lambda x: x[1], reverse=True)
            for channel, count in sorted_channels[:5]:
                print(f"  Channel {channel}: {count} networks")

        print()

class WiFiManager:
    """WiFi connection and hosted network management"""

    @staticmethod
    def get_current_connection() -> Optional[Dict[str, str]]:
        """Get current WiFi connection info"""
        output = SystemUtils.run_command('netsh wlan show interfaces')
        if not output:
            return None

        info = {}
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()

        return info if info else None

    @staticmethod
    def create_hotspot(ssid: str, password: str, max_clients: int = 10) -> bool:
        """Create WiFi hotspot"""
        if not Validator.ssid(ssid):
            Printer.error("Invalid SSID (1-32 characters)")
            return False

        if not Validator.password(password, 8):
            Printer.error("Password must be at least 8 characters")
            return False

        Printer.info(f"Creating hotspot: {ssid}")
        SystemUtils.run_command('netsh wlan stop hostednetwork')

        cmd = f'netsh wlan set hostednetwork mode=allow ssid="{ssid}" key="{password}"'
        if not SystemUtils.run_command(cmd, capture=False):
            Printer.error("Failed to configure hotspot")
            return False

        if SystemUtils.run_command('netsh wlan start hostednetwork', capture=False):
            Printer.success(f"Hotspot '{ssid}' started successfully!")
            Printer.info(f"Password: {password}")
            return True
        else:
            Printer.error("Failed to start hotspot. Your adapter may not support hosted networks.")
            return False

    @staticmethod
    def stop_hotspot() -> bool:
        """Stop WiFi hotspot"""
        if SystemUtils.run_command('netsh wlan stop hostednetwork', capture=False):
            Printer.success("Hotspot stopped")
            return True
        return False

    @staticmethod
    def get_hotspot_status() -> Optional[str]:
        """Get hotspot status"""
        output = SystemUtils.run_command('netsh wlan show hostednetwork')
        if output:
            print(output)
            return output
        return None

class MACSpoofer:
    """MAC address spoofing"""

    REGISTRY_KEY = r'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'

    @staticmethod
    def spoof(interface: str, mac: Optional[str] = None, vendor: Optional[str] = None) -> bool:
        """Spoof MAC address"""
        if not mac:
            if vendor:
                mac = MACGenerator.vendor_mac(vendor)
                if not mac:
                    Printer.error(f"Unknown vendor: {vendor}")
                    return False
                Printer.info(f"Using {vendor} MAC: {mac}")
            else:
                mac = MACGenerator.random_mac()
                Printer.info(f"Using random MAC: {mac}")

        if not Validator.mac_address(mac):
            Printer.error("Invalid MAC address format")
            return False

        current_mac = NetworkInterface.get_mac(interface)
        if current_mac:
            Printer.info(f"Current MAC: {current_mac}")
            ConfigManager.set(f'mac_backup_{interface}', current_mac)

        mac_no_sep = mac.replace(':', '').replace('-', '').upper()

        Printer.info("Updating registry...")
        success = False

        for i in range(0, 100):
            reg_path = f"{MACSpoofer.REGISTRY_KEY}\\{str(i).zfill(4)}"
            check_cmd = f'reg query "{reg_path}" /v DriverDesc 2>nul'
            result = SystemUtils.run_command(check_cmd)
            
            if result and (interface.lower() in result.lower() or 'wireless' in result.lower() or 'wi-fi' in result.lower()):
                add_cmd = f'reg add "{reg_path}" /v "NetworkAddress" /d {mac_no_sep} /f'
                if SystemUtils.run_command(add_cmd, capture=False):
                    Printer.success(f"Registry updated: {reg_path}")
                    success = True
                    break

        if not success:
            for i in range(0, 20):
                reg_path = f"{MACSpoofer.REGISTRY_KEY}\\{str(i).zfill(4)}"
                add_cmd = f'reg add "{reg_path}" /v "NetworkAddress" /d {mac_no_sep} /f 2>nul'
                if SystemUtils.run_command(add_cmd, capture=False):
                    success = True

        if success and NetworkInterface.restart(interface):
            time.sleep(3)
            new_mac = NetworkInterface.get_mac(interface)
            if new_mac:
                if new_mac.upper().replace(':', '') == mac_no_sep:
                    Printer.success(f"MAC spoofed successfully: {new_mac}")
                else:
                    Printer.warning(f"MAC changed: {new_mac}")
                return True

        Printer.error("Failed to spoof MAC address")
        return False

    @staticmethod
    def reset(interface: str) -> bool:
        """Reset MAC to hardware default"""
        Printer.info("Resetting MAC to hardware default...")

        for i in range(0, 100):
            reg_path = f"{MACSpoofer.REGISTRY_KEY}\\{str(i).zfill(4)}"
            delete_cmd = f'reg delete "{reg_path}" /v "NetworkAddress" /f 2>nul'
            SystemUtils.run_command(delete_cmd)

        if NetworkInterface.restart(interface):
            time.sleep(3)
            new_mac = NetworkInterface.get_mac(interface)
            if new_mac:
                Printer.success(f"MAC reset to: {new_mac}")
                return True

        Printer.error("Failed to reset MAC")
        return False

class NetworkScanner:
    """Network device scanning"""

    @staticmethod
    def arp_scan() -> List[NetworkDevice]:
        """Scan network using ARP"""
        Printer.info("Scanning network via ARP...")
        devices = []

        output = SystemUtils.run_command('arp -a')
        if not output:
            Printer.error("ARP scan failed")
            return devices

        current_interface = None
        timestamp = datetime.now().isoformat()

        for line in output.split('\n'):
            if 'Interface:' in line:
                match = re.search(r'Interface:\s+([\d\.]+)', line)
                if match:
                    current_interface = match.group(1)
                    print(f"\n{Colors.MAGENTA}{Colors.BOLD}Interface: {current_interface}{Colors.RESET}")
                    print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}")
                continue

            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)', line)
            if match:
                ip, mac, type_ = match.groups()

                if mac == 'ff-ff-ff-ff-ff-ff' or type_ == 'invalid':
                    continue

                device = NetworkDevice(
                    ip=ip,
                    mac=mac.replace('-', ':'),
                    type=type_,
                    interface=current_interface or 'Unknown',
                    first_seen=timestamp,
                    last_seen=timestamp
                )
                devices.append(device)

                type_color = Colors.GREEN if type_ == 'dynamic' else Colors.YELLOW
                print(f"  {Colors.CYAN}IP:{Colors.RESET} {ip:<15} {Colors.MAGENTA}MAC:{Colors.RESET} {device.mac:<20} {type_color}Type:{Colors.RESET} {type_}")

        print(f"{Colors.CYAN}{'─'*70}{Colors.RESET}\n")
        Printer.success(f"Found {len(devices)} devices")

        return devices

    @staticmethod
    def ping_sweep(subnet: str = "192.168.1", save: bool = True) -> List[str]:
        """Perform ping sweep on subnet"""
        Printer.info(f"Ping sweep on {subnet}.0/24")
        alive_hosts = []
        total = 254

        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            Printer.progress_bar(i, total, "Scanning")

            result = SystemUtils.run_command(f'ping -n 1 -w 100 {ip}', timeout=2)
            if result and 'Reply from' in result:
                alive_hosts.append(ip)

        print()
        Printer.success(f"Found {len(alive_hosts)} alive hosts")

        if alive_hosts:
            print(f"\n{Colors.GREEN}Alive hosts:{Colors.RESET}")
            for ip in alive_hosts:
                print(f"  • {ip}")

        if save and alive_hosts:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ping_sweep_{timestamp}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Ping Sweep Results - {timestamp}\n")
                    f.write(f"Subnet: {subnet}.0/24\n")
                    f.write(f"Alive hosts: {len(alive_hosts)}\n\n")
                    for ip in alive_hosts:
                        f.write(f"{ip}\n")
                Printer.info(f"Results saved to {filename}")
            except Exception as e:
                Printer.error(f"Failed to save results: {e}")

        return alive_hosts

    @staticmethod
    def port_scan(ip: str, ports: List[int] = None) -> Dict[int, bool]:
        """Basic port scan"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

        Printer.info(f"Scanning ports on {ip}")
        results = {}

        import socket

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                results[port] = (result == 0)
                sock.close()

                if results[port]:
                    print(f"  {Colors.GREEN}Port {port} OPEN{Colors.RESET}")
            except:
                results[port] = False

        return results

class ReportGenerator:
    """Generate security reports"""

    @staticmethod
    def generate_network_report(networks: List[WiFiNetwork], devices: List[NetworkDevice]) -> str:
        """Generate comprehensive network report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""
{'='*80}
NETWORK SECURITY ASSESSMENT REPORT
{'='*80}
Generated: {timestamp}
Tool: Advanced WiFi Security Tool v{Config.VERSION}

{'='*80}
1. WIFI NETWORK SCAN
{'='*80}

Total Networks Found: {len(networks)}

"""

        for i, net in enumerate(networks, 1):
            security_level = net.get_security_level()
            report += f"""
Network #{i}:
  SSID: {net.ssid}
  Signal: {net.signal}%
  Channel: {net.channel}
  Security: {net.security or 'Unknown'} ({security_level.value})
  BSSID: {net.bssid or 'N/A'}
  Encryption: {net.encryption or 'N/A'}
"""

        analysis = WiFiScanner.analyze_networks(networks)

        report += f"""
{'='*80}
2. SECURITY ANALYSIS
{'='*80}

Security Distribution:
  Open Networks: {analysis['open']}
  WEP: {analysis['wep']}
  WPA: {analysis['wpa']}
  WPA2: {analysis['wpa2']}
  WPA3: {analysis['wpa3']}

"""

        if analysis['weak_security']:
            report += "⚠ Networks with Weak Security:\n"
            for ssid, reason in analysis['weak_security']:
                report += f"  • {ssid}: {reason}\n"

        report += f"""
{'='*80}
3. NETWORK DEVICES
{'='*80}

Total Devices Found: {len(devices)}

"""

        for i, device in enumerate(devices, 1):
            report += f"""
Device #{i}:
  IP: {device.ip}
  MAC: {device.mac}
  Type: {device.type}
  Interface: {device.interface}
"""

        report += f"""
{'='*80}
4. RECOMMENDATIONS
{'='*80}

"""

        recommendations = []

        if analysis['open'] > 0:
            recommendations.append("• Avoid connecting to open WiFi networks without VPN")

        if analysis['wep'] > 0:
            recommendations.append("• WEP is deprecated and insecure. Avoid WEP networks")

        if analysis['wpa'] > 0:
            recommendations.append("• WPA is outdated. Prefer WPA2 or WPA3 networks")

        recommendations.append("• Use strong, unique passwords for WiFi networks")
        recommendations.append("• Enable WPA3 if supported by your router")
        recommendations.append("• Regularly update router firmware")
        recommendations.append("• Disable WPS (WiFi Protected Setup)")
        recommendations.append("• Use a VPN on public networks")

        report += "\n".join(recommendations)

        report += f"""

{'='*80}
END OF REPORT
{'='*80}
"""

        return report

    @staticmethod
    def save_report(report: str, filename: Optional[str] = None) -> bool:
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_report_{timestamp}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            Printer.success(f"Report saved: {filename}")
            return True
        except Exception as e:
            Printer.error(f"Failed to save report: {e}")
            return False

# ==================== INTERACTIVE MENU ====================
class Menu:
    """Interactive menu system"""

    @staticmethod
    def banner():
        """Display banner"""
        SystemUtils.clear_screen()

        banner_art = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗  ║
║    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗ ║
║    ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║ ║
║    ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║ ║
║    ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝ ║
║    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝  ║
║                                                                          ║
║            WiFi Security & Network Analysis Tool v{Config.VERSION}                ║
║                   Professional Penetration Testing Suite                ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}{Colors.BOLD}        ⚠  FOR AUTHORIZED SECURITY TESTING ONLY  ⚠{Colors.RESET}
{Colors.RED}   Unauthorized access to networks is illegal and unethical{Colors.RESET}

"""
        print(banner_art)

        system_info = SystemUtils.get_system_info()
        print(f"{Colors.DIM}System: {system_info.get('OS')} | User: {system_info.get('User')} | Computer: {system_info.get('Computer')}{Colors.RESET}\n")

    @staticmethod
    def main_menu():
        """Display main menu"""
        print(f"""
{Colors.YELLOW}{Colors.BOLD}╔═══════════════════════ MAIN MENU ═══════════════════════╗{Colors.RESET}
{Colors.CYAN}║                                                         ║
║  {Colors.BOLD}[1] WiFi Operations{Colors.RESET}{Colors.CYAN}                                    ║
║  {Colors.BOLD}[2] MAC Address Spoofing{Colors.RESET}{Colors.CYAN}                               ║
║  {Colors.BOLD}[3] Network Scanning{Colors.RESET}{Colors.CYAN}                                   ║
║  {Colors.BOLD}[4] Interface Management{Colors.RESET}{Colors.CYAN}                               ║
║  {Colors.BOLD}[5] Reports & Analysis{Colors.RESET}{Colors.CYAN}                                 ║
║  {Colors.BOLD}[6] Settings & Logs{Colors.RESET}{Colors.CYAN}                                    ║
║  {Colors.BOLD}[0] Exit{Colors.RESET}{Colors.CYAN}                                               ║
║                                                         ║{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}╚═════════════════════════════════════════════════════════╝{Colors.RESET}
""")

    @staticmethod
    def wifi_menu():
        """WiFi operations submenu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}=== WiFi Operations ==={Colors.RESET}")
            print("1. Scan nearby networks")
            print("2. Show current connection")
            print("3. Create hotspot")
            print("4. Stop hotspot")
            print("5. Hotspot status")
            print("0. Back to main menu")

            choice = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

            if choice == "1":
                networks = WiFiScanner.scan()
                WiFiScanner.display_networks(networks)
                analysis = WiFiScanner.analyze_networks(networks)
                WiFiScanner.display_analysis(analysis)

                ConfigManager.set('last_scan', {
                    'timestamp': datetime.now().isoformat(),
                    'networks': [asdict(n) for n in networks]
                })

            elif choice == "2":
                info = WiFiManager.get_current_connection()
                if info:
                    Printer.section("Current WiFi Connection")
                    for key, value in info.items():
                        if value:
                            print(f"{Colors.CYAN}{key}:{Colors.RESET} {value}")
                else:
                    Printer.warning("Not connected to WiFi")

            elif choice == "3":
                ssid = input(f"{Colors.CYAN}Enter SSID: {Colors.RESET}").strip()
                password = input(f"{Colors.CYAN}Enter password (min 8 chars): {Colors.RESET}").strip()
                WiFiManager.create_hotspot(ssid, password)

            elif choice == "4":
                WiFiManager.stop_hotspot()

            elif choice == "5":
                WiFiManager.get_hotspot_status()

            elif choice == "0":
                break

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    @staticmethod
    def mac_menu():
        """MAC spoofing submenu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}=== MAC Address Spoofing ==={Colors.RESET}")
            print("1. Spoof MAC (random)")
            print("2. Spoof MAC (specific)")
            print("3. Spoof MAC (vendor)")
            print("4. Reset MAC to default")
            print("5. View current MAC addresses")
            print("0. Back to main menu")

            choice = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

            interfaces = NetworkInterface.list_all()

            if choice in ["1", "2", "3", "4"]:
                if not interfaces:
                    Printer.error("No interfaces found")
                    continue

                print(f"\n{Colors.CYAN}Select interface:{Colors.RESET}")
                for i, iface in enumerate(interfaces, 1):
                    print(f"  {i}. {iface.name} ({iface.status})")

                try:
                    idx = int(input(f"{Colors.MAGENTA}Enter number: {Colors.RESET}")) - 1
                    if 0 <= idx < len(interfaces):
                        interface = interfaces[idx].name
                    else:
                        Printer.error("Invalid selection")
                        continue
                except ValueError:
                    Printer.error("Invalid input")
                    continue

            if choice == "1":
                MACSpoofer.spoof(interface)

            elif choice == "2":
                mac = input(f"{Colors.CYAN}Enter MAC address: {Colors.RESET}").strip()
                MACSpoofer.spoof(interface, mac)

            elif choice == "3":
                vendors = MACGenerator.get_vendors()
                print(f"\n{Colors.CYAN}Available vendors:{Colors.RESET}")
                for i, vendor in enumerate(vendors, 1):
                    print(f"  {i}. {vendor}")

                try:
                    idx = int(input(f"{Colors.MAGENTA}Select vendor: {Colors.RESET}")) - 1
                    if 0 <= idx < len(vendors):
                        MACSpoofer.spoof(interface, vendor=vendors[idx])
                except ValueError:
                    Printer.error("Invalid input")

            elif choice == "4":
                MACSpoofer.reset(interface)

            elif choice == "5":
                Printer.section("Network Interface MAC Addresses")
                for iface in interfaces:
                    status_color = Colors.GREEN if iface.status == "Connected" else Colors.RED
                    print(f"{Colors.CYAN}{iface.name}:{Colors.RESET}")
                    print(f"  MAC: {iface.mac or 'N/A'}")
                    print(f"  Status: {status_color}{iface.status}{Colors.RESET}")
                    print(f"  IP: {iface.ip or 'N/A'}")
                    print()

            elif choice == "0":
                break

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    @staticmethod
    def scan_menu():
        """Network scanning submenu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}=== Network Scanning ==={Colors.RESET}")
            print("1. ARP scan (LAN devices)")
            print("2. Ping sweep")
            print("3. Port scan")
            print("4. Full network audit")
            print("0. Back to main menu")

            choice = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

            if choice == "1":
                devices = NetworkScanner.arp_scan()
                ConfigManager.set('last_arp_scan', {
                    'timestamp': datetime.now().isoformat(),
                    'devices': [asdict(d) for d in devices]
                })

            elif choice == "2":
                subnet = input(f"{Colors.CYAN}Enter subnet (e.g., 192.168.1): {Colors.RESET}").strip()
                if not subnet:
                    subnet = "192.168.1"
                NetworkScanner.ping_sweep(subnet)

            elif choice == "3":
                ip = input(f"{Colors.CYAN}Enter target IP: {Colors.RESET}").strip()
                if Validator.ip_address(ip):
                    results = NetworkScanner.port_scan(ip)
                    open_ports = [p for p, open_val in results.items() if open_val]
                    Printer.info(f"Open ports: {len(open_ports)}")
                else:
                    Printer.error("Invalid IP address")

            elif choice == "4":
                Printer.info("Performing full network audit...")
                networks = WiFiScanner.scan()
                devices = NetworkScanner.arp_scan()

                report = ReportGenerator.generate_network_report(networks, devices)
                print(report)

                save = input(f"\n{Colors.CYAN}Save report? (y/n): {Colors.RESET}").strip().lower()
                if save == 'y':
                    ReportGenerator.save_report(report)

            elif choice == "0":
                break

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    @staticmethod
    def interface_menu():
        """Interface management submenu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}=== Interface Management ==={Colors.RESET}")
            print("1. List all interfaces")
            print("2. Restart interface")
            print("3. Enable interface")
            print("4. Disable interface")
            print("0. Back to main menu")

            choice = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

            interfaces = NetworkInterface.list_all()

            if choice == "1":
                Printer.section("Network Interfaces")
                for iface in interfaces:
                    status_color = Colors.GREEN if iface.status == "Connected" else Colors.RED
                    print(f"{Colors.BOLD}{iface.name}{Colors.RESET}")
                    print(f"  Status: {status_color}{iface.status}{Colors.RESET}")
                    print(f"  MAC: {iface.mac or 'N/A'}")
                    print(f"  IP: {iface.ip or 'N/A'}")
                    print(f"  Gateway: {iface.gateway or 'N/A'}")
                    print()

            elif choice in ["2", "3", "4"]:
                if not interfaces:
                    Printer.error("No interfaces found")
                    continue

                print(f"\n{Colors.CYAN}Select interface:{Colors.RESET}")
                for i, iface in enumerate(interfaces, 1):
                    print(f"  {i}. {iface.name}")

                try:
                    idx = int(input(f"{Colors.MAGENTA}Enter number: {Colors.RESET}")) - 1
                    if 0 <= idx < len(interfaces):
                        interface = interfaces[idx].name
                    else:
                        continue
                except ValueError:
                    continue

                if choice == "2":
                    NetworkInterface.restart(interface)
                elif choice == "3":
                    NetworkInterface.enable(interface)
                elif choice == "4":
                    NetworkInterface.disable(interface)

            elif choice == "0":
                break

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    @staticmethod
    def settings_menu():
        """Settings and logs submenu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}=== Settings & Logs ==={Colors.RESET}")
            print("1. View recent logs")
            print("2. View configuration")
            print("3. Clear logs")
            print("4. System information")
            print("5. About")
            print("0. Back to main menu")

            choice = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

            if choice == "1":
                logs = Logger.get_recent_logs(50)
                Printer.section("Recent Log Entries")
                for log in logs:
                    print(log.strip())

            elif choice == "2":
                config = ConfigManager.load()
                Printer.section("Configuration")
                print(json.dumps(config, indent=2))

            elif choice == "3":
                confirm = input(f"{Colors.YELLOW}Clear all logs? (yes/no): {Colors.RESET}").strip().lower()
                if confirm == "yes":
                    try:
                        open(Config.LOG_FILE, 'w').close()
                        Printer.success("Logs cleared")
                    except Exception as e:
                        Printer.error(f"Failed to clear logs: {e}")

            elif choice == "4":
                info = SystemUtils.get_system_info()
                Printer.section("System Information")
                for key, value in info.items():
                    print(f"{Colors.CYAN}{key}:{Colors.RESET} {value}")

            elif choice == "5":
                Printer.section("About")
                print(f"{Colors.BOLD}Advanced WiFi Security Tool{Colors.RESET}")
                print(f"Version: {Config.VERSION}")
                print(f"Platform: Windows")
                print(f"\n{Colors.YELLOW}⚠ Educational & Authorized Testing Only{Colors.RESET}")
                print("This tool is designed for security professionals and")
                print("network administrators to test and secure their networks.")

            elif choice == "0":
                break

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

# ==================== MAIN APPLICATION ====================
def main():
    """Main application entry point"""
        
        
        

    Logger.log("Application started", "SYSTEM")

    try:
        while True:
            Menu.banner()
            Menu.main_menu()

            choice = input(f"{Colors.MAGENTA}{Colors.BOLD}[?] Select option: {Colors.RESET}").strip()
            print()

            try:
                if choice == "1":
                    Menu.wifi_menu()
                elif choice == "2":
                    Menu.mac_menu()
                elif choice == "3":
                    Menu.scan_menu()
                elif choice == "4":
                    Menu.interface_menu()
                elif choice == "5":
                    print(f"\n{Colors.CYAN}{Colors.BOLD}=== Reports & Analysis ==={Colors.RESET}")
                    print("1. Generate security report")
                    print("2. View last scan")

                    sub = input(f"\n{Colors.MAGENTA}Select option: {Colors.RESET}").strip()

                    if sub == "1":
                        Printer.info("Scanning networks for report...")
                        networks = WiFiScanner.scan()
                        devices = NetworkScanner.arp_scan()

                        report = ReportGenerator.generate_network_report(networks, devices)
                        print(report)

                        save = input(f"\n{Colors.CYAN}Save report? (y/n): {Colors.RESET}").strip().lower()
                        if save == 'y':
                            ReportGenerator.save_report(report)

                    elif sub == "2":
                        last_scan = ConfigManager.get('last_scan')
                        if last_scan:
                            Printer.section("Last WiFi Scan")
                            print(f"Timestamp: {last_scan['timestamp']}")
                            print(f"Networks found: {len(last_scan['networks'])}")

                            for net_data in last_scan['networks'][:10]:
                                print(f"\n  • {net_data['ssid']}")
                                print(f"    Signal: {net_data.get('signal', 'N/A')}%")
                                print(f"    Security: {net_data.get('security', 'Unknown')}")
                        else:
                            Printer.warning("No scan history available")

                elif choice == "6":
                    Menu.settings_menu()

                elif choice == "0":
                    Printer.info("Shutting down...")
                    Logger.log("Application closed by user", "SYSTEM")
                    print(f"\n{Colors.GREEN}Thank you for using Advanced WiFi Security Tool!{Colors.RESET}")
                    sys.exit(0)

                else:
                    Printer.error("Invalid option. Please try again.")

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Operation interrupted by user{Colors.RESET}")

            except Exception as e:
                Printer.error(f"An error occurred: {e}")
                Logger.log(f"Error in menu: {e}", "ERROR")

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Exiting...{Colors.RESET}")
        Logger.log("Application interrupted by user", "SYSTEM")
        sys.exit(0)

    except Exception as e:
        Printer.critical(f"Fatal error: {e}")
        Logger.log(f"Fatal error: {e}", "CRITICAL")
        sys.exit(1)

# ==================== COMMAND LINE INTERFACE ====================
def cli_mode():
    """Command-line interface mode for automation"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Advanced WiFi Security Tool - CLI Mode',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--scan', action='store_true', help='Scan WiFi networks')
    parser.add_argument('--arp', action='store_true', help='Perform ARP scan')
    parser.add_argument('--ping-sweep', metavar='SUBNET', help='Ping sweep (e.g., 192.168.1)')
    parser.add_argument('--spoof-mac', metavar='INTERFACE', help='Spoof MAC address')
    parser.add_argument('--mac', metavar='MAC', help='Specific MAC address for spoofing')
    parser.add_argument('--vendor', metavar='VENDOR', help='Vendor for MAC spoofing')
    parser.add_argument('--reset-mac', metavar='INTERFACE', help='Reset MAC to default')
    parser.add_argument('--report', action='store_true', help='Generate security report')
    parser.add_argument('--output', metavar='FILE', help='Output file for reports')

    args = parser.parse_args()

    if not SystemUtils.is_admin():
        Printer.critical("Administrator privileges required!")
        sys.exit(1)

    if args.scan:
        networks = WiFiScanner.scan()
        WiFiScanner.display_networks(networks)
        analysis = WiFiScanner.analyze_networks(networks)
        WiFiScanner.display_analysis(analysis)

    elif args.arp:
        NetworkScanner.arp_scan()

    elif args.ping_sweep:
        NetworkScanner.ping_sweep(args.ping_sweep)

    elif args.spoof_mac:
        MACSpoofer.spoof(args.spoof_mac, mac=args.mac, vendor=args.vendor)

    elif args.reset_mac:
        MACSpoofer.reset(args.reset_mac)

    elif args.report:
        Printer.info("Generating report...")
        networks = WiFiScanner.scan()
        devices = NetworkScanner.arp_scan()
        report = ReportGenerator.generate_network_report(networks, devices)

        if args.output:
            ReportGenerator.save_report(report, args.output)
        else:
            print(report)

    else:
        parser.print_help()

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    if os.name != "nt":
        print(f"{Colors.RED}[!] This tool is designed for Windows only.{Colors.RESET}")
        sys.exit(1)

    if len(sys.argv) > 1:
        cli_mode()
    else:
        main()