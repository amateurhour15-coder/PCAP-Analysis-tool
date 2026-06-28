"""Configuration management for NetSleuth."""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Configuration file path
CONFIG_DIR = Path("config")
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Default configuration
DEFAULT_CONFIG = {
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    },
    "database": {
        "path": "data/netsleuth.db",
    },
    "pcap": {
        "buffer_size": 65536,
        "timeout": 30,
    },
    "oui": {
        "cache_enabled": True,
        "cache_size": 10000,
    },
    "network": {
        "resolve_hostnames": True,
        "max_dns_queries": 1000,
    },
}


class Config:
    """Configuration manager."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration.
        
        Args:
            config_path: Path to YAML config file
        """
        self.config_path = config_path or CONFIG_FILE
        self.config: Dict[str, Any] = DEFAULT_CONFIG.copy()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        # Deep merge
                        self._deep_merge(self.config, user_config)
                    logger.info(f"Configuration loaded from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}. Using defaults.")
        else:
            logger.debug(f"Config file not found at {self.config_path}. Using defaults.")
    
    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge override config into base.
        
        Args:
            base: Base configuration dict
            override: Override configuration dict
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.
        
        Args:
            key: Configuration key (dot-separated for nested keys)
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        keys = key.split(".")
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, path: Optional[Path] = None) -> None:
        """Save configuration to YAML file.
        
        Args:
            path: Output path (default: config file path)
        """
        path = path or self.config_path
        path.parent.mkdir(exist_ok=True)
        
        try:
            with open(path, "w") as f:
                yaml.dump(self.config, f, default_flow_style=False)
            logger.info(f"Configuration saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance.
    
    Returns:
        Configuration instance
    """
    global _config
    if _config is None:
        _config = Config()
    return _config
