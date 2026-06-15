import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple
from utils.logger import setup_logger

logger = setup_logger("subdomain_finder")

def check_subdomain(subdomain: str, domain: str) -> Optional[Tuple[str, str]]:
    """
    Attempts to resolve a subdomain to an IP address.
    Returns a tuple of (full_subdomain, ip) if successful, otherwise None.
    """
    target = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror:
        return None
    except Exception as e:
        logger.debug(f"Error checking subdomain {target}: {e}")
        return None

def run(domain: str) -> Dict[str, Any]:
    """
    Checks common subdomains against the target domain.
    Returns a structured dictionary of discovered subdomains and their IP addresses.
    """
    logger.info(f"Starting subdomain search for domain: {domain}")
    
    results: Dict[str, Any] = {
        "domain": domain,
        "subdomains": []
    }
    
    common_subdomains = [
        "admin",
        "api",
        "test",
        "mail",
        "dev",
        "staging",
        "www",
        "blog",
        "shop",
        "secure",
        "portal",
        "cdn"
    ]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_subdomain, sub, domain) for sub in common_subdomains]
        for future in futures:
            res = future.result()
            if res:
                sub_domain, ip = res
                results["subdomains"].append({
                    "subdomain": sub_domain,
                    "ip": ip
                })
                logger.debug(f"Found subdomain: {sub_domain} -> {ip}")
                
    if not results["subdomains"]:
        logger.info("No common subdomains found.")
        
    return results

if __name__ == "__main__":
    from pprint import pprint
    pprint(run("example.com"))
