from typing import Dict, Any, List, Optional
import yaml
from pathlib import Path
import re
import logging

class SecurityRule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.syscall = rule_data.get('syscall', '')
        self.allowed_users = rule_data.get('allowed_users', [])
        self.allowed_processes = rule_data.get('allowed_processes', [])
        self.parameter_rules = rule_data.get('parameter_rules', {})
        self.risk_level = rule_data.get('risk_level', 'low')
        
    def matches_pattern(self, value: str, pattern: str) -> bool:
        """Check if value matches a pattern (supports wildcards)"""
        pattern = pattern.replace('*', '.*')
        return bool(re.match(f"^{pattern}$", value))

class SecurityValidator:
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path or str(Path(__file__).parent.parent / "config/security_rules.yaml")
        self.rules: Dict[str, SecurityRule] = {}
        self._load_security_rules()
        
    def _load_security_rules(self):
        """Load security rules from configuration file"""
        try:
            if not Path(self.config_path).exists():
                self._create_default_rules()
                
            with open(self.config_path, 'r') as f:
                rules_data = yaml.safe_load(f)
                
            for syscall, rule_data in rules_data.items():
                self.rules[syscall] = SecurityRule(rule_data)
        except Exception as e:
            self.logger.error(f"Error loading security rules: {e}")
            self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default security rules"""
        default_rules = {
            'open': {
                'syscall': 'open',
                'allowed_users': ['*'],
                'allowed_processes': ['*'],
                'parameter_rules': {
                    'path': ['^/home/', '^/tmp/'],
                    'flags': ['O_RDONLY']
                },
                'risk_level': 'medium'
            },
            'write': {
                'syscall': 'write',
                'allowed_users': ['*'],
                'allowed_processes': ['*'],
                'parameter_rules': {
                    'count': {'max': 1048576}  # 1MB max write
                },
                'risk_level': 'medium'
            },
            'exec': {
                'syscall': 'exec*',
                'allowed_users': ['root', 'admin'],
                'allowed_processes': ['bash', 'sh', 'python*'],
                'risk_level': 'high'
            }
        }
        
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(default_rules, f)
        
        for syscall, rule_data in default_rules.items():
            self.rules[syscall] = SecurityRule(rule_data)
    
    def validate_syscall(self, syscall_info: Dict[str, Any], process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a system call against security rules
        Returns validation result with status and any security warnings
        """
        syscall_name = syscall_info.get('name', '')
        matching_rule = None
        
        # Find matching rule (including wildcard patterns)
        for rule_name, rule in self.rules.items():
            if rule.matches_pattern(syscall_name, rule.syscall):
                matching_rule = rule
                break
        
        if not matching_rule:
            return {
                'allowed': True,
                'risk_level': 'unknown',
                'warnings': ['No security rule defined for this system call']
            }
        
        warnings = []
        username = process_info.get('username', '')
        process_name = process_info.get('name', '')
        
        # Check user permission
        user_allowed = any(
            rule.matches_pattern(username, allowed_user)
            for allowed_user in matching_rule.allowed_users
        )
        if not user_allowed:
            warnings.append(f"User {username} is not allowed to make this system call")
        
        # Check process permission
        process_allowed = any(
            rule.matches_pattern(process_name, allowed_process)
            for allowed_process in matching_rule.allowed_processes
        )
        if not process_allowed:
            warnings.append(f"Process {process_name} is not allowed to make this system call")
        
        # Validate parameters
        args = syscall_info.get('arguments', {})
        for param_name, rules in matching_rule.parameter_rules.items():
            if param_name in args:
                value = args[param_name]
                if isinstance(rules, list):  # Pattern matching
                    if not any(re.match(pattern, str(value)) for pattern in rules):
                        warnings.append(f"Invalid value for parameter {param_name}")
                elif isinstance(rules, dict):  # Numeric constraints
                    if 'max' in rules and value > rules['max']:
                        warnings.append(f"Value for {param_name} exceeds maximum allowed")
                    if 'min' in rules and value < rules['min']:
                        warnings.append(f"Value for {param_name} below minimum allowed")
        
        return {
            'allowed': len(warnings) == 0,
            'risk_level': matching_rule.risk_level,
            'warnings': warnings
        }
