import hashlib
import os
import time
import psutil
import socket
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(filename='security_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# File Integrity Monitoring
class FileIntegrityMonitor:
    def __init__(self, directory):
        self.directory = directory
        self.baseline = {}

    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error hashing {filepath}: {e}")
            return None

    def create_baseline(self):
        """Create baseline hashes for all files in directory."""
        self.baseline = {}
        for root, _, files in os.walk(self.directory):
            for file in files:
                filepath = os.path.join(root, file)
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    self.baseline[filepath] = file_hash
        logging.info("File integrity baseline created.")

    def check_integrity(self):
        """Check for file changes against baseline."""
        for root, _, files in os.walk(self.directory):
            for file in files:
                filepath = os.path.join(root, file)
                current_hash = self.calculate_hash(filepath)
                if filepath not in self.baseline:
                    logging.warning(f"New file detected: {filepath}")
                elif current_hash != self.baseline[filepath]:
                    logging.warning(f"File modified: {filepath}")

# Network Intrusion Detection
class NetworkMonitor:
    def __init__(self, suspicious_ports=[4444, 6667]):  # Example suspicious ports
        self.suspicious_ports = suspicious_ports
        self.known_ips = set()

    def monitor_connections(self):
        """Monitor active network connections for suspicious activity."""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.laddr.port in self.suspicious_ports:
                    logging.warning(f"Suspicious connection detected: {conn.laddr} -> {conn.raddr}")
                if conn.raddr and conn.raddr.ip:
                    ip = conn.raddr.ip
                    if ip not in self.known_ips:
                        self.known_ips.add(ip)
                        self.check_ip_reputation(ip)
        except Exception as e:
            logging.error(f"Error monitoring network: {e}")

    def check_ip_reputation(self, ip):
        """Placeholder for IP reputation check (integrate with external API in production)."""
        logging.info(f"Checking reputation for IP: {ip}")
        # In a real tool, query a threat intelligence API like VirusTotal

# Malware Scanner
class MalwareScanner:
    def __init__(self):
        # Example malware signatures (hashes of known malicious files)
        self.malware_signatures = {
            'eicar_test': '44d88612fea8a8f36de82e1278abb02f'  # EICAR test file hash
        }

    def scan_file(self, filepath):
        """Scan a file for known malware signatures."""
        file_hash = self.calculate_hash(filepath)
        if file_hash in self.malware_signatures.values():
            logging.critical(f"Malware detected: {filepath} (Hash: {file_hash})")
            return True
        return False

    def scan_directory(self, directory):
        """Scan all files in a directory for malware."""
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                self.scan_file(filepath)

    def calculate_hash(self, filepath):
        """Calculate MD5 hash for malware scanning."""
        md5 = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
            return md5.hexdigest()
        except Exception as e:
            logging.error(f"Error scanning {filepath}: {e}")
            return None

# Main Security Tool
def main():
    print("Starting Security Tool - Inspired by Pakistani Ethical Hackers")
    logging.info("Security tool started.")

    # Initialize components
    monitor_dir = "C:/important_files"  # Change to directory to monitor
    file_monitor = FileIntegrityMonitor(monitor_dir)
    network_monitor = NetworkMonitor()
    malware_scanner = MalwareScanner()

    # Create file integrity baseline
    file_monitor.create_baseline()

    # Main monitoring loop
    while True:
        try:
            # Check file integrity
            file_monitor.check_integrity()

            # Monitor network
            network_monitor.monitor_connections()

            # Scan for malware
            malware_scanner.scan_directory(monitor_dir)

            print(f"[{datetime.now()}] Security check completed. Sleeping for 60 seconds.")
            time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            print("Shutting down security tool.")
            logging.info("Security tool stopped.")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()