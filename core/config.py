"""
WazuhBoard Configuration Management
Handles multi-tenant configuration from mt_config.yaml and environment variables
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration manager for WazuhBoard"""
    
    def __init__(self):
        """Initialize configuration from environment and YAML"""
        self.env = {
            "mt_enabled": os.getenv("MT_ENABLED", "false").lower() == "true",
            "dashboard_host": os.getenv("MT_DASHBOARD_HOST", "localhost"),
            "dashboard_port": int(os.getenv("MT_DASHBOARD_PORT", 9200)),
            "dashboard_user": os.getenv("MT_DASHBOARD_USER"),
            "dashboard_pass": os.getenv("MT_DASHBOARD_PASS"),
            "use_opensearch": os.getenv("MT_USE_OPENSEARCH", "false").lower() == "true",
            "verify_ssl": os.getenv("MT_VERIFY_SSL", "true").lower() == "true",
            "index_pattern": os.getenv("MT_INDEX_PATTERN", "*:wazuh-alerts*"),
        }
        
        # Load multi-tenant configuration
        self.mt_config = self._load_mt_config()
    
    def _load_mt_config(self) -> Dict[str, Any]:
        """Load multi-tenant configuration from mt_config.yaml"""
        try:
            if os.path.exists("mt_config.yaml"):
                with open("mt_config.yaml", "r") as f:
                    config = yaml.safe_load(f)
                    logger.info("Loaded mt_config.yaml")
                    return config.get("multi_tenant", {}) if config else {}
        except Exception as e:
            logger.warning(f"Could not load mt_config.yaml: {e}")
        
        # Return default config if file not found
        return {
            "enabled": False,
            "client_configs": {},
            "default_client_config": {}
        }
    
    def get_client_names(self) -> List[str]:
        """
        Get list of configured client names from mt_config.yaml
        
        Returns:
            List of client names (e.g., ['lab', 'homelab', 'production'])
        """
        configs = self.mt_config.get("client_configs", {})
        return list(configs.keys()) if configs else []
    
    def get_default_client(self) -> Optional[str]:
        """
        Get default client name (first in list)
        
        Returns:
            First client name or None
        """
        clients = self.get_client_names()
        return clients[0] if clients else None
    
    def get_client_display_name(self, client_name: str) -> str:
        """
        Get human-readable display name for a client
        
        Args:
            client_name: Client identifier (e.g., 'lab')
            
        Returns:
            Display name from config or client name if not found
        """
        configs = self.mt_config.get("client_configs", {})
        if client_name in configs:
            return configs[client_name].get("display_name", client_name)
        return client_name
    
    def get_client_config(self, client_name: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Get full configuration for a specific client
        
        Args:
            client_name: Client identifier
            
        Returns:
            Client config dict or None
        """
        if not client_name:
            return None
        
        configs = self.mt_config.get("client_configs", {})
        return configs.get(client_name)
    
    def get_elasticsearch_config(self, client_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get Elasticsearch connection configuration
        Uses environment variables for all clients (single Elasticsearch instance)
        
        Args:
            client_name: Optional client name (for index scoping, not connection)
            
        Returns:
            Dict with host, port, scheme, username, password, verify_ssl
        """
        dashboard_host = self.env["dashboard_host"]
        
        # Determine scheme from host URL
        if dashboard_host.startswith("https://"):
            scheme = "https"
            host = dashboard_host.replace("https://", "").replace("http://", "").rstrip("/")
        elif dashboard_host.startswith("http://"):
            scheme = "http"
            host = dashboard_host.replace("http://", "").rstrip("/")
        else:
            scheme = "https" if "https" in dashboard_host else "http"
            host = dashboard_host.rstrip("/")
        
        return {
            "host": host,
            "port": self.env["dashboard_port"],
            "scheme": scheme,
            "username": self.env["dashboard_user"],
            "password": self.env["dashboard_pass"],
            "verify_ssl": self.env["verify_ssl"]
        }


# Global config instance - used across the application
config = Config()