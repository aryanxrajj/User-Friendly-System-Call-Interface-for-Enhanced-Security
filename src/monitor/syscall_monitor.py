import psutil
from ptrace import PtraceError
from ptrace.debugger import PtraceDebugger, ProcessSignal, ProcessExit
from ptrace.func_call import FunctionCallOptions
from typing import Dict, Any, List, Optional, Callable
import logging
from datetime import datetime
from queue import Queue
import threading
import time
import os
import json
from collections import defaultdict, deque
from pathlib import Path

class SyscallMonitor:
    # High-risk system calls that could indicate potential security threats
    HIGH_RISK_SYSCALLS = {
        'execve', 'fork', 'clone', 'ptrace', 'mount', 'chmod', 'chown',
        'setuid', 'setgid', 'setreuid', 'setregid'
    }
    
    def __init__(self):
        self.debugger = PtraceDebugger()
        self.monitored_processes: Dict[int, Any] = {}
        self.running = False
        self.callback: Optional[Callable] = None
        self.event_queue = Queue()
        self._setup_logging()
        
        # Configure ptrace options
        self.func_call_options = FunctionCallOptions(
            write_types=True,
            string_max_length=300,
            replace_socketcall=False,
            write_argname=True,
            write_address=True
        )
        
        # Track process states
        self.process_states = {}
        
    def _setup_logging(self):
        """Configure enhanced logging for system call monitoring"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(process)d] - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('syscall_monitor.log'),
                logging.FileHandler('security_alerts.log', mode='a')
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_security_config(self):
        """Load security configuration from file"""
        config_path = Path('security_config.json')
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = json.load(f)
                self.syscall_whitelist = set(config.get('whitelist', []))
                self.syscall_blacklist = set(config.get('blacklist', []))
                self.rate_limits.update(config.get('rate_limits', {}))
                self.logger.info("Loaded security configuration")
            except Exception as e:
                self.logger.error(f"Error loading security config: {e}")

    def check_syscall_allowed(self, syscall_name: str) -> bool:
        """Check if a system call is allowed based on white/blacklist"""
        if syscall_name in self.syscall_blacklist:
            return False
        if self.syscall_whitelist and syscall_name not in self.syscall_whitelist:
            return False
        return True

    def check_rate_limit(self, pid: int, syscall_name: str) -> bool:
        """Check if the syscall exceeds rate limits"""
        now = time.time()
        
        # Categorize the syscall
        category = 'general'
        if syscall_name in {'open', 'read', 'write', 'close'}:
            category = 'file_ops'
        elif syscall_name in {'socket', 'connect', 'bind', 'listen'}:
            category = 'network'
        elif syscall_name in {'fork', 'clone', 'execve'}:
            category = 'process'

        # Check rate limit
        last_time = self.last_call_times[pid][category]
        if now - last_time < 1.0:  # Within 1 second window
            calls = len([t for t in self.call_history[pid] if t > now - 1.0])
            if calls >= self.rate_limits[category]:
                return False
        
        self.last_call_times[pid][category] = now
        self.call_history[pid].append(now)
        return True

    def detect_privilege_escalation(self, syscall_info: Dict[str, Any]) -> bool:
        """Detect potential privilege escalation attempts"""
        name = syscall_info['name']
        if name in self.HIGH_RISK_SYSCALLS:
            proc = psutil.Process(syscall_info['pid'])
            try:
                if proc.username() != 'root' and name in {'setuid', 'setgid', 'setreuid', 'setregid'}:
                    self.logger.warning(f"Potential privilege escalation attempt by pid {syscall_info['pid']}")
                    return True
            except psutil.NoSuchProcess:
                pass
        return False

    def get_syscall_info(self, process) -> Dict[str, Any]:
        """Get enhanced information about the current system call"""
        try:
            syscall = process.syscall_state
            if not syscall:
                return {}

            info = {
                'time': datetime.now().strftime('%H:%M:%S.%f'),
                'pid': process.pid,
                'name': syscall.name,
                'arguments': syscall.arguments,
                'result': syscall.result,
                'status': 'completed' if syscall.result is not None else 'in_progress'
            }

            # Security checks
            if not self.check_syscall_allowed(syscall.name):
                info['blocked'] = True
                self.logger.warning(f"Blocked unauthorized syscall {syscall.name} from pid {process.pid}")
                return info

            if not self.check_rate_limit(process.pid, syscall.name):
                info['blocked'] = True
                self.violation_counts[process.pid] += 1
                self.logger.warning(f"Rate limit exceeded for {syscall.name} by pid {process.pid}")
                return info

            if self.detect_privilege_escalation(info):
                info['security_alert'] = 'privilege_escalation'

            # Monitor resource usage
            try:
                proc = psutil.Process(process.pid)
                info['resource_usage'] = {
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'num_threads': proc.num_threads(),
                    'open_files': len(proc.open_files()),
                    'connections': len(proc.connections())
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            return info

        except Exception as e:
            self.logger.error(f"Error getting syscall info: {e}")
            return {}

    def attach_process(self, pid: int) -> bool:
        """
        Attach to a process for monitoring its system calls
        Returns True if successful, False otherwise
        """
        if not self.check_permissions():
            self.logger.error(f"[{os.getpid()}] - Root privileges required to attach to processes")
            return False
            
        try:
            if pid in self.monitored_processes:
                return True

            # Check if process is still running
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    self.logger.error(f"[{os.getpid()}] - Process {pid} is not running")
                    return False
                    
                # Store process info
                self.process_states[pid] = {
                    'name': proc.name(),
                    'create_time': proc.create_time(),
                    'status': proc.status()
                }
                
            except psutil.NoSuchProcess:
                self.logger.error(f"[{os.getpid()}] - Process {pid} does not exist")
                return False
            except psutil.AccessDenied:
                self.logger.error(f"[{os.getpid()}] - Access denied to process {pid}")
                return False

            # Attempt to attach with improved error handling
            try:
                process = self.debugger.addProcess(pid, True)
                if process:
                    process.syscall()  # Enter syscall trace mode
                    self.monitored_processes[pid] = process
                    self.logger.info(f"[{os.getpid()}] - Successfully attached to process {pid} ({self.process_states[pid]['name']})")
                    return True
                else:
                    self.logger.error(f"[{os.getpid()}] - Failed to attach to process {pid}: debugger returned None")
                    return False
            except PtraceError as e:
                self.logger.error(f"[{os.getpid()}] - PtraceError attaching to process {pid}: {e}")
                return False
            except Exception as e:
                self.logger.error(f"[{os.getpid()}] - Unexpected error attaching to process {pid}: {e}")
                return False

        except Exception as e:
            self.logger.error(f"[{os.getpid()}] - Critical error in attach_process for {pid}: {e}")
            return False

    def _monitor_thread(self):
        """Enhanced monitoring thread with better error handling"""
        while self.running:
            try:
                for pid, process in list(self.monitored_processes.items()):
                    if not process.is_attached:
                        self.logger.warning(f"[{os.getpid()}] - Process {pid} detached, removing from monitored list")
                        del self.monitored_processes[pid]
                        continue

                    try:
                        if not psutil.pid_exists(pid):
                            self.logger.info(f"[{os.getpid()}] - Process {pid} no longer exists, removing from monitored list")
                            del self.monitored_processes[pid]
                            continue

                        event = process.waitEvent(True)  # Non-blocking wait
                        
                        if event is None:
                            continue
                            
                        if isinstance(event, ProcessExit):
                            self.logger.info(f"[{os.getpid()}] - Process {pid} exited")
                            del self.monitored_processes[pid]
                            continue
                            
                        if isinstance(event, ProcessSignal):
                            process.syscall()
                            continue
                            
                        syscall = process.syscall_state
                        if syscall:
                            syscall_info = self.get_syscall_info(process)
                            if syscall_info and self.callback:
                                self.event_queue.put(syscall_info)
                        
                        process.syscall()  # Resume until next syscall
                        
                    except ProcessExit:
                        self.logger.info(f"[{os.getpid()}] - Process {pid} exited during monitoring")
                        del self.monitored_processes[pid]
                    except PtraceError as e:
                        self.logger.error(f"[{os.getpid()}] - Error monitoring process {pid}: {e}")
                        del self.monitored_processes[pid]
                    except Exception as e:
                        self.logger.error(f"[{os.getpid()}] - Unexpected error monitoring process {pid}: {e}")
                        del self.monitored_processes[pid]

            except Exception as e:
                self.logger.error(f"[{os.getpid()}] - Error in monitor thread: {e}")
            finally:
                time.sleep(0.01)  # Short sleep to prevent CPU overload

    def set_callback(self, callback: Callable):
        """Set callback function for system call events"""
        self.callback = callback
    
    def check_permissions(self) -> bool:
        """Check if we have the necessary permissions"""
        return os.geteuid() == 0
    
    def detach_process(self, pid: int) -> bool:
        """Detach from a monitored process"""
        try:
            if pid in self.monitored_processes:
                process = self.monitored_processes[pid]
                process.detach()
                del self.monitored_processes[pid]
                self.logger.info(f"[{os.getpid()}] - Detached from process {pid}")
                return True
            return False
        except PtraceError as e:
            self.logger.error(f"[{os.getpid()}] - Failed to detach from process {pid}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"[{os.getpid()}] - Unexpected error detaching from process {pid}: {e}")
            return False
    
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.check_permissions():
            self.logger.error(f"[{os.getpid()}] - Root privileges required to start monitoring")
            return False
            
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_thread)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info(f"[{os.getpid()}] - Started system call monitoring")
            return True
        return False
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1.0)
        for pid in list(self.monitored_processes.keys()):
            self.detach_process(pid)
        self.logger.info(f"[{os.getpid()}] - Stopped system call monitoring")
    
    def get_available_processes(self) -> List[Dict[str, Any]]:
        """Get list of available processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                processes.append({
                    'pid': proc.pid,
                    'name': proc.name(),
                    'username': proc.username()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes
