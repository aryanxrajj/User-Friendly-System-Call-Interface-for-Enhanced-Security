from typing import Dict, Any
import yaml
from pathlib import Path

class SecurityValidator:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or str(Path(__file__).parent / "../config/security_rules.yaml")
        self.security_rules = self._load_security_rules()
    
    def _load_security_rules(self) -> Dict[str, Any]:
        """Load security rules from configuration file"""
        if not Path(self.config_path).exists():
            return {}
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def validate_syscall(self, syscall_name: str, parameters: Dict[str, Any]) -> bool:
        """
        Validate a system call and its parameters against security rules
        Returns True if the call is allowed, False otherwise
        """
        if syscall_name not in self.security_rules:
            return False
            
        rule = self.security_rules[syscall_name]
        return self._check_parameters(parameters, rule)
