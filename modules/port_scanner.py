import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple
from utils.logger import setup_logger

logger = setup_logger("port_scanner")

def scan_port(target: str, port: int) -> Optional[Tuple[int, str, str]]:
    """
    Attempts to connect to a specific port on the target.
    Returns a tuple of (port, status, service) if open, otherwise None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except socket.error:
                service = "Unknown"
            sock.close()
            return port, "OPEN", service
        sock.close()
    except Exception as e:
        logger.debug(f"Error scanning port {port} on {target}: {e}")
    return None

def run(target: str) -> Dict[str, Any]:
    """
    Scans ports 1-1024 on the target domain/IP.
    Returns a structured dictionary with the scan results.
    """
    logger.info(f"Starting port scan on target: {target}")
    
    results: Dict[str, Any] = {
        "target": target,
        "open_ports": []
    }
    
    # Scanning ports 1-1024
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port) for port in range(1, 1025)]
        for future in futures:
            res = future.result()
            if res:
                port, status, service = res
                results["open_ports"].append({
                    "port": port,
                    "status": status,
                    "service": service.upper()
                })
                logger.debug(f"Discovered open port: {port}/tcp ({service})")
                
    if not results["open_ports"]:
        logger.info("No open ports found in range 1-1024.")
        
    return results

if __name__ == "__main__":
    # Test
    from pprint import pprint
    pprint(run("scanme.nmap.org"))
