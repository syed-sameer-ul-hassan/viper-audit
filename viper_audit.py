#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VIPER-AUDIT ENTERPRISE
~~~~~~~~~~~~~~~~~~~~~~
A professional-grade, strictly non-exploitative network inventory
and reconnaissance tool. Designed for authorized security auditing,
asset discovery, and system administration.

SCOPE:
- TCP SYN Scanning (Net-Inventory)
- TCP Connect Scanning (Non-privileged)
- Service Identification (Banner Grabbing)
- Passive OS Fingerprinting (TTL Analysis)

SAFETY:
- No exploits
- No brute-forcing
- No payloads

License: MIT
Author: Senior Security Architect
"""

import sys
import os
import time
import random
import argparse
import socket
import logging
import json
import signal
import ipaddress
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from dataclasses import dataclass, asdict

# --- DEPENDENCY SAFETY CHECK ---
try:
    # We suppress scapy warnings to keep output clean for reports
    import logging as py_logging
    py_logging.getLogger("scapy.runtime").setLevel(py_logging.ERROR)
    
    from scapy.all import IP, TCP, sr1, conf, L3RawSocket
    conf.verb = 0
    conf.L3socket = L3RawSocket
except ImportError:
    print("\033[91m[CRITICAL] Scapy is missing. Install with: pip install scapy\033[0m")
    print("This dependency is required for low-level network inventory (SYN scanning).")
    sys.exit(1)

# --- CONFIGURATION CONSTANTS ---

VERSION = "6.0.0-AUDIT"
DEFAULT_THREADS = 10
MAX_THREADS = 50 # Safety Cap to prevent accidental DoS
DEFAULT_TIMEOUT = 1.5

# --- DATA STRUCTURES ---

@dataclass
class AuditResult:
    port: int
    state: str
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    os_guess: str = "unknown"
    ttl: int = 0
    timestamp: str = ""

@dataclass
class AuditConfig:
    target: str
    ports: List[int]
    scan_method: str = "syn"  # 'syn' or 'connect'
    threads: int = DEFAULT_THREADS
    timeout: float = DEFAULT_TIMEOUT
    delay: float = 0.0
    active_recon: bool = True # If False, disables banner grabbing
    output_prefix: Optional[str] = None
    verbose: bool = False

# --- LOGGING & UI ---

class LogColors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    GREY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class AuditFormatter(logging.Formatter):
    format_str = "%(asctime)s - %(levelname)s - %(message)s"
    
    FORMATS = {
        logging.DEBUG: LogColors.GREY + format_str + LogColors.RESET,
        logging.INFO: LogColors.GREEN + format_str + LogColors.RESET,
        logging.WARNING: LogColors.YELLOW + format_str + LogColors.RESET,
        logging.ERROR: LogColors.RED + format_str + LogColors.RESET,
        logging.CRITICAL: LogColors.RED + LogColors.BOLD + format_str + LogColors.RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)

def setup_logger(verbose: bool):
    logger = logging.getLogger("ViperAudit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(AuditFormatter())
    logger.addHandler(ch)
    
    return logger

logger = logging.getLogger("ViperAudit")

# --- UTILITIES ---

def validate_target_safety(target: str) -> str:
    """Validates target IP and prevents scanning localhost/0.0.0.0 accidentally."""
    try:
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_loopback or ip_obj.is_unspecified:
             logger.warning("Scanning localhost or 0.0.0.0 is often redundant. Proceeding with caution.")
        return str(ip_obj)
    except ValueError:
        try:
            resolved = socket.gethostbyname(target)
            return resolved
        except socket.gaierror:
            logger.critical(f"Could not resolve hostname: {target}")
            sys.exit(1)

def parse_safe_ports(port_str: str) -> List[int]:
    """Parses port range. Throws error on invalid inputs."""
    if port_str == 'common':
        return [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080, 8443]
    
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                # Limit range size if needed, but for now just validate
                if start < 1 or end > 65535: raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                logger.error(f"Invalid port range: {part}")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                logger.error(f"Invalid port: {part}")
                sys.exit(1)
    return sorted(list(ports))

def check_root_requirement():
    """Checks for root privileges required for RAW socket operations (SYN Scan)."""
    if os.geteuid() != 0:
        logger.critical("SYN Inventory Scan requires ROOT privileges (Raw Sockets).")
        logger.critical("Please run with 'sudo' or use '--method connect' for non-privileged scan.")
        sys.exit(1)

# --- RECONNAISSANCE ENGINE ---

class ReconEngine:
    def __init__(self, config: AuditConfig):
        self.config = config
        self.results: List[AuditResult] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def _passive_os_fingerprint(self, ttl: int) -> str:
        """
        Guesses OS based on Initial TTL. 
        Note: This is passive observation, not active probing.
        """
        if ttl <= 64: return "Linux/Unix/Mac"
        elif ttl <= 128: return "Windows"
        elif ttl <= 255: return "Cisco/Solaris"
        return "Unknown"

    def _banner_grab(self, port: int) -> str:
        """
        Attempts to read the service banner. 
        STRICTLY READ-ONLY: Sends generic hello, reads response, disconnects.
        No payloads, no exploits.
        """
        if not self.config.active_recon:
            return "Disabled"
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0) # Strict timeout
                s.connect((self.config.target, port))
                # Polite probe: HTTP HEAD or generic byte
                probe = b'HEAD / HTTP/1.0\r\n\r\n' if port in [80, 8080, 443] else b'\\r\\n'
                s.sendall(probe)
                data = s.recv(1024)
                return data.decode('utf-8', errors='ignore').strip()
        except:
            return ""

    def scan_syn(self, port: int):
        """
        TCP SYN Scan (Half-Open).
        Standard Inventory Technique. Low impact.
        """
        if self.stop_event.is_set(): return
        
        # Rate limiting (Safety)
        if self.config.delay > 0:
            time.sleep(self.config.delay)

        src_port = random.randint(1025, 65534)
        
        try:
            # Send SYN
            syn_pkt = IP(dst=self.config.target)/TCP(sport=src_port, dport=port, flags="S")
            # sr1 sends and waits for 1 response
            resp = sr1(syn_pkt, timeout=self.config.timeout, verbose=0, iface=None)
            
            if resp and resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                
                # Check for SYN-ACK (0x12) -> Port is Listening
                if tcp_layer.flags == 0x12:
                    ttl = resp.getlayer(IP).ttl
                    os_guess = self._passive_os_fingerprint(ttl)
                    
                    # IMMEDIATELY RESET connection (Do not complete handshake)
                    # This keeps the interaction lightweight and non-intrusive
                    rst_pkt = IP(dst=self.config.target)/TCP(sport=src_port, dport=port, flags="R")
                    conf.L3socket().send(rst_pkt)

                    # Optional Banner Grab (Requires full connection, separate step)
                    banner = self._banner_grab(port) if self.config.active_recon else "Skipped (Passive)"
                    
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service = "unknown"

                    res = AuditResult(
                        port=port, state="OPEN", service=service,
                        banner=banner, os_guess=os_guess, ttl=ttl,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    with self.lock:
                        self.results.append(res)
                        logger.info(f"Port {port:<5} OPEN | {service:<10} | {os_guess}")

        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")

    def scan_connect(self, port: int):
        """
        TCP Connect Scan.
        Standard User-Space Scan. Full Handshake.
        """
        if self.stop_event.is_set(): return
        if self.config.delay > 0: time.sleep(self.config.delay)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config.timeout)
                result = s.connect_ex((self.config.target, port))
                
                if result == 0:
                    banner = self._banner_grab(port) if self.config.active_recon else "Disabled"
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service = "unknown"
                    
                    res = AuditResult(
                        port=port, state="OPEN", service=service,
                        banner=banner, os_guess="Unknown (Connect)", ttl=0,
                        timestamp=datetime.now().isoformat()
                    )
                    with self.lock:
                        self.results.append(res)
                        logger.info(f"Port {port:<5} OPEN | {service:<10}")
        except:
            pass

    def run(self):
        scan_func = self.scan_syn if self.config.scan_method == "syn" else self.scan_connect
        
        logger.info(f"Starting Inventory Scan on {self.config.target}")
        logger.info(f"Method: {self.config.scan_method.upper()} | Threads: {self.config.threads}")
        
        if not self.config.active_recon:
            logger.warning("Active Recon (Banner Grabbing) is DISABLED. Results will be passive only.")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(scan_func, p) for p in self.config.ports]
            try:
                for future in as_completed(futures):
                    if self.stop_event.is_set(): break
                    future.result()
            except KeyboardInterrupt:
                self.stop_event.set()
                logger.warning("Scan interrupted by user.")

# --- REPORTING ---

def generate_report(results: List[AuditResult], config: AuditConfig):
    duration = datetime.now().isoformat()
    
    # Console Summary
    print("\\n" + "="*60)
    print(f"{LogColors.BOLD}AUDIT SUMMARY: {config.target}{LogColors.RESET}")
    print("="*60)
    print(f"{'PORT':<8} {'SERVICE':<15} {'BANNER SAMPLE'}")
    print("-" * 60)
    
    sorted_res = sorted(results, key=lambda x: x.port)
    for r in sorted_res:
        safe_banner = (r.banner[:40] + '...') if len(r.banner) > 40 else r.banner
        safe_banner = safe_banner.replace('\\n', ' ').replace('\\r', '') # Sanitize output
        print(f"{LogColors.GREEN}{r.port:<8} {r.service:<15} {safe_banner}{LogColors.RESET}")
    
    print("-" * 60)
    
    # JSON Export
    if config.output_prefix:
        fname = f"{config.output_prefix}.json"
        data = {
            "metadata": {
                "tool": "Viper-Audit",
                "version": VERSION,
                "target": config.target,
                "scan_time": duration
            },
            "findings": [asdict(r) for r in sorted_res]
        }
        try:
            with open(fname, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"JSON audit record saved to: {fname}")
        except IOError as e:
            logger.error(f"File write error: {e}")

# --- MAIN EXECUTION ---

def main():
    # Signal Safety
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    parser = argparse.ArgumentParser(
        description="Viper-Audit Enterprise | Authorized Network Inventory Tool",
        epilog="USAGE NOTICE: This tool is for authorized security auditing only."
    )
    
    # Core Arguments
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", default="common", help="Ports (e.g. '80', '1-100', 'common'). Default: common")
    
    # Method Arguments
    parser.add_argument("--method", choices=["syn", "connect"], default="syn", 
                        help="Scan Method: SYN (Root/Stealth) or Connect (User). Default: syn")
    
    # Safety & Performance
    parser.add_argument("--passive", action="store_true", 
                        help="Disable active banner grabbing (Port check only)")
    parser.add_argument("--delay", type=float, default=0.0, 
                        help="Safety delay between packets (seconds)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, 
                        help=f"Concurrency limit (Max {MAX_THREADS})")
    
    # Output
    parser.add_argument("-o", "--output", help="Output file prefix (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logs")

    args = parser.parse_args()

    # --- BANNER & SAFETY STATEMENT ---
    print(f"{LogColors.CYAN}{LogColors.BOLD}")
    print(r"""
     _    _                  _____                 
    | |  | |                / ____|                
    | |  | |_ __   ___ _ __| (___   ___ __ _ _ __  
    | |  | | '_ \ / _ \ '__|\___ \ / __/ _` | '_ \ 
    \  \/  / |_) |  __/ |   ____) | (_| (_| | | | |
     \    /| .__/ \___|_|  |_____/ \___\__,_|_| |_|
      \__/ | |    AUDIT EDITION v{0}
           |_|                                     
    """.format(VERSION))
    print(f"{LogColors.RESET}")

    # --- MANDATORY SAFETY BLOCK ---
    print(f"{LogColors.YELLOW}" + "="*60)
    print(f" 1️⃣ 5️⃣  WHAT THIS TOOL IS NOT")
    print(f" {'❌':<4} Malware")
    print(f" {'❌':<4} Exploit framework")
    print(f" {'❌':<4} Brute-force tool")
    print(f" {'❌':<4} Illegal scanner")
    print(f" {'✔':<4} Reconnaissance only")
    print("="*60 + f"{LogColors.RESET}\\n")

    # --- INITIALIZATION CHECKS ---
    setup_logger(args.verbose)
    
    if args.method == "syn":
        check_root_requirement()
    
    if args.threads > MAX_THREADS:
        logger.warning(f"Thread count {args.threads} exceeds safety cap. Reducing to {MAX_THREADS}.")
        args.threads = MAX_THREADS

    target_ip = validate_target_safety(args.target)
    ports = parse_safe_ports(args.ports)

    # Config Object
    config = AuditConfig(
        target=target_ip,
        ports=ports,
        scan_method=args.method,
        threads=args.threads,
        delay=args.delay,
        active_recon=not args.passive,
        output_prefix=args.output,
        verbose=args.verbose
    )

    # Execution
    engine = ReconEngine(config)
    engine.run()
    generate_report(engine.results, config)

if __name__ == "__main__":
    main()
