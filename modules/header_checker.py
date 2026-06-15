import requests
import urllib3
from typing import Dict, Any
from utils.logger import setup_logger

# Suppress insecure request warnings for https without verify
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger("header_checker")

def run(target: str) -> Dict[str, Any]:
    """
    Checks the target URL for common security headers.
    Returns a structured dictionary with the found and missing headers.
    """
    # Ensure it has a scheme
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = "https://" + target
    else:
        target_url = target
        
    logger.info(f"Starting security headers check for target: {target_url}")
    
    results: Dict[str, Any] = {
        "target": target_url,
        "found": [],
        "missing": [],
        "error": None
    }
    
    headers_to_check = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-XSS-Protection": "X-XSS-Protection"
    }
    
    try:
        response = requests.get(target_url, verify=False, timeout=10)
        headers = response.headers
        
        for header, name in headers_to_check.items():
            if header in headers:
                results["found"].append(name)
            else:
                results["missing"].append(name)
                
        logger.debug(f"Checked headers for {target_url}. Found {len(results['found'])}.")
                
    except Exception as e:
        logger.error(f"Error fetching headers: {e}")
        results["error"] = str(e)
        
    return results

if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
