import whois
from typing import Dict, Any
from utils.logger import setup_logger

logger = setup_logger("whois_lookup")

def run(domain: str) -> Dict[str, Any]:
    """
    Performs a WHOIS lookup for the target domain.
    Returns a structured dictionary with registrar and date information.
    """
    logger.info(f"Starting WHOIS lookup for domain: {domain}")
    
    results: Dict[str, Any] = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "error": None
    }
    
    try:
        w = whois.whois(domain)
        
        registrar = w.registrar
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        # Handle lists in dates (sometimes WHOIS returns lists)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        # Format dates if they are datetime objects
        if hasattr(creation_date, "strftime"):
            creation_date = creation_date.strftime("%Y-%m-%d %H:%M:%S")
        if hasattr(expiration_date, "strftime"):
            expiration_date = expiration_date.strftime("%Y-%m-%d %H:%M:%S")
            
        results["registrar"] = registrar
        results["creation_date"] = creation_date
        results["expiration_date"] = expiration_date
        
        logger.debug(f"WHOIS Lookup successful for {domain}.")
        
    except Exception as e:
        logger.error(f"Error performing WHOIS lookup: {e}")
        results["error"] = str(e)
        
    return results

if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
