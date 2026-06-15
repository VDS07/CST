"""
Port Scanner module for CyberShield Toolkit.

Performs multi-threaded TCP connect scanning across a configurable
port range. Each port is probed in its own thread using a non-blocking
socket with a short timeout, and results are aggregated into a sorted
list of open ports with service name resolution.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Tuple
from utils.logger import setup_logger

logger = setup_logger("port_scanner")

# Well-known port range defaults
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 100


def scan_port(target: str, port: int, timeout: float) -> Optional[Tuple[int, str, str]]:
    """
    Attempt a TCP connection to a single port on the target host.

    Args:
        target: Hostname or IP address to probe.
        port: TCP port number to connect to.
        timeout: Connection timeout in seconds.

    Returns:
        A tuple of ``(port, status, service)`` if the port is open,
        or ``None`` if the connection was refused or timed out.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return port, "OPEN", service
    except socket.timeout:
        logger.debug(f"Timeout on port {port}")
    except OSError as exc:
        logger.debug(f"Error scanning port {port} on {target}: {exc}")
    finally:
        sock.close()
    return None


def run(
    target: str,
    start_port: int = DEFAULT_START_PORT,
    end_port: int = DEFAULT_END_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_WORKERS,
) -> Dict[str, Any]:
    """
    Scan a range of TCP ports on the target and return open ones.

    Args:
        target: Hostname or IP address to scan.
        start_port: First port in the scan range (inclusive).
        end_port: Last port in the scan range (inclusive).
        timeout: Per-port connection timeout in seconds.
        max_workers: Maximum number of concurrent scanning threads.

    Returns:
        A dictionary containing the target, open ports list
        (sorted by port number), port range metadata, and elapsed time.
    """
    logger.info(f"Starting port scan on {target} [{start_port}-{end_port}]")

    results: Dict[str, Any] = {
        "target": target,
        "ports_scanned": f"{start_port}-{end_port}",
        "open_ports": [],
        "scan_duration_seconds": 0.0,
    }

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            port_result = future.result()
            if port_result:
                port_num, status, service = port_result
                results["open_ports"].append({
                    "port": port_num,
                    "status": status,
                    "service": service.upper(),
                })
                logger.debug(f"Open: {port_num}/tcp ({service})")

    elapsed = time.time() - start_time
    results["scan_duration_seconds"] = round(elapsed, 2)

    # Sort by port number for clean output
    results["open_ports"].sort(key=lambda p: p["port"])

    if not results["open_ports"]:
        logger.info(f"No open ports found in range {start_port}-{end_port}.")
    else:
        logger.info(f"Found {len(results['open_ports'])} open port(s) in {elapsed:.2f}s.")

    return results


if __name__ == "__main__":
    from pprint import pprint
    pprint(run("scanme.nmap.org"))
