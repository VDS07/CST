import dns.resolver
from typing import Dict, Any, List
from utils.logger import setup_logger

logger = setup_logger("dns_lookup")

def run(domain: str) -> Dict[str, Any]:
    """
    Performs a DNS lookup for A, MX, and NS records for the target domain.
    Returns a structured dictionary with the discovered records.
    """
    logger.info(f"Starting DNS lookup for domain: {domain}")
    
    results: Dict[str, Any] = {
        "domain": domain,
        "A": [],
        "MX": [],
        "NS": []
    }
    
    # A Record
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            results["A"].append(rdata.address)
        logger.debug(f"Found {len(results['A'])} A records.")
    except Exception as e:
        logger.debug(f"A Record lookup failed or empty: {e}")
        
    # MX Record
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            results["MX"].append(rdata.exchange.to_text())
        logger.debug(f"Found {len(results['MX'])} MX records.")
    except Exception as e:
        logger.debug(f"MX Record lookup failed or empty: {e}")
        
    # NS Record
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            results["NS"].append(rdata.target.to_text())
        logger.debug(f"Found {len(results['NS'])} NS records.")
    except Exception as e:
        logger.debug(f"NS Record lookup failed or empty: {e}")

    return results

if __name__ == "__main__":
    from pprint import pprint
    pprint(run("google.com"))
