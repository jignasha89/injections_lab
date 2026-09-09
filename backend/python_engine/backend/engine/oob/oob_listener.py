import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class OOBListener:
    """
    Stub for Out-of-Band (OOB) DNS/HTTP callback listener.
    Phase 5D implementation.
    """
    def __init__(self, callback_domain: Optional[str] = None):
        self.callback_domain = callback_domain
        self._is_running = False
        self.hits = {} # Store hits by unique token

    async def start(self):
        if not self.callback_domain:
            logger.info("OOB callback domain not configured. OOB listener disabled.")
            return
        
        self._is_running = True
        logger.info(f"OOB listener starting for domain: {self.callback_domain}")
        # In a real implementation, this would bind to port 53/80/443
        # and parse incoming requests.

    async def stop(self):
        self._is_running = False
        logger.info("OOB listener stopped.")

    def check_hit(self, token: str) -> bool:
        """Check if a specific OOB token was received."""
        return self.hits.get(token, False)
        
    def register_hit(self, token: str):
        """Used by the actual server listener to register a hit."""
        self.hits[token] = True
        logger.info(f"OOB hit registered for token: {token}")
