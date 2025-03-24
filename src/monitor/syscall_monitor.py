import psutil
from typing import Dict, Any, List, Optional, Callable
import logging
from datetime import datetime
from queue import Queue
import threading
import time
import os
import json
import sys
import subprocess
from collections import defaultdict, deque
from pathlib import Path
import random
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

class SyscallMonitor:
    # High-risk system calls that could indicate potential security threats
    HIGH_RISK_SYSCALLS = {
        'execve', 'fork', 'clone', 'ptrace', 'mount', 'chmod', 'chown',
        'setuid', 'setgid', 'setreuid', 'setregid'
    }
    
    # System call categories for better organization
    SYSCALL_CATEGORIES = {
        'file_ops': {'open', 'read', 'write', 'close', 'unlink', 'rename', 'mkdir', 'rmdir'},
        'network': {'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv'},
        'process': {'fork', 'clone', 'execve', 'exit', 'kill'},
        'memory': {'mmap', 'munmap', 'mprotect', 'brk'},
        'security': {'chmod', 'chown', 'setuid', 'setgid', 'capset'},
        'ipc': {'pipe', 'socket', 'msgget', 'semget', 'shmget'}
    }
    
    def __init__(self):
        self.monitored_processes: Dict[int, Any] = {}
        self.running = False
        self.callback: Optional[Callable] = None
        self.event_queue = Queue()
        self._setup_logging()
        self.start_time = None
        self.stop_time = None
        self.syscall_logs = defaultdict(list)
        
        # Initialize tracking structures
        self.process_states = {}
        self.syscall_counts = defaultdict(int)
        self.last_call_times = defaultdict(lambda: defaultdict(float))
        self.call_history = defaultdict(lambda: deque(maxlen=1000))
        self.violation_counts = defaultdict(int)
        self.rate_limits = {
            'file_ops': 1000,  # calls per second
            'network': 500,
            'process': 100,
            'general': 2000
        }
        
        # DTrace process
        self.dtrace_process = None
        self.monitor_thread = None
        
    def _get_category(self, syscall_name: str) -> str:
        """Get the category of a system call"""
        for category, calls in self.SYSCALL_CATEGORIES.items():
            if syscall_name in calls:
                return category
        return 'other'
        
    def _get_risk_level(self, syscall_name: str, process_info: Dict[str, Any]) -> str:
        """Determine risk level of a system call based on various factors"""
        if syscall_name in self.HIGH_RISK_SYSCALLS:
            return 'high'
            
        # Check for suspicious combinations
        if syscall_name == 'open' and process_info.get('username') != 'root':
            if any(arg.startswith('/etc/') or arg.startswith('/usr/') for arg in process_info.get('cmdline', [])):
                return 'medium'
                
        if self.violation_counts[process_info['pid']] > 5:
            return 'high'
            
        if syscall_name in self.SYSCALL_CATEGORIES['network']:
            return 'medium'
            
        return 'low'

    def start_monitoring(self, pid: int):
        """Start monitoring a specific process"""
        if not self.attach_process(pid):
            self.logger.error(f"Failed to attach process with PID: {pid}")
            return False
        
        self.logger.info(f"Started monitoring process with PID: {pid}")
        self.start_time = datetime.now()
        
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
        
        return True

    def stop_monitoring(self):
        """Stop monitoring all processes"""
        self.logger.info("Stopped monitoring all processes")
        self.running = False
        self.stop_time = datetime.now()
        if self.monitor_thread:
            self.monitor_thread.join()
        self.monitored_processes.clear()

    def _monitor_loop(self):
        """Main monitoring loop"""
        self.logger.debug("Entering monitor loop")
        while self.running:
            try:
                self.logger.debug("Iterating over monitored processes")
                for pid in list(self.monitored_processes.keys()):
                    try:
                        proc = psutil.Process(pid)
                        
                        # Get process information
                        proc_info = {
                            'pid': pid,
                            'name': proc.name(),
                            'username': proc.username(),
                            'cmdline': proc.cmdline(),
                            'cpu_percent': proc.cpu_percent(),
                            'memory_percent': proc.memory_percent(),
                            'num_threads': proc.num_threads(),
                            'status': proc.status()
                        }
                        
                        self.logger.debug(f"Monitoring process: {proc_info}")
                        
                        # Simulate system calls for testing
                        self._simulate_syscalls(pid, proc_info)
                        
                    except psutil.NoSuchProcess:
                        self.logger.warning(f"Process with PID {pid} no longer exists")
                        self.monitored_processes.pop(pid, None)
                        continue
                        
                time.sleep(0.1)  # Prevent excessive CPU usage
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                
    def _simulate_syscalls(self, pid: int, proc_info: Dict[str, Any]):
        """Simulate system calls for testing and demonstration"""
        common_syscalls = [
            ('open', '/etc/passwd', 'high'),
            ('read', '/usr/bin/python', 'low'),
            ('socket', 'AF_INET', 'medium'),
            ('connect', '192.168.1.1:80', 'medium'),
            ('write', '/tmp/test.txt', 'low'),
            ('fork', '', 'high'),
            ('mmap', '0x1000', 'low')
        ]
        
        for syscall, arg, base_risk in common_syscalls:
            if random.random() < 0.3:  # 30% chance to generate each syscall
                category = self._get_category(syscall)
                risk_level = self._get_risk_level(syscall, proc_info)
                
                syscall_info = {
                    'pid': pid,
                    'name': syscall,
                    'category': category,
                    'arguments': {'arg': arg},
                    'time': datetime.now().strftime('%H:%M:%S.%f'),
                    'status': 'completed',
                    'risk_level': risk_level,
                    'process_info': proc_info
                }
                
                self.syscall_logs[pid].append(syscall_info)
                
                if self.callback:
                    self.callback(syscall_info)
                    
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

    def get_syscall_info(self, syscall_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get enhanced information about the current system call"""
        try:
            # Security checks
            if not self.check_syscall_allowed(syscall_info['name']):
                syscall_info['blocked'] = True
                self.logger.warning(f"Blocked unauthorized syscall {syscall_info['name']} from pid {syscall_info['pid']}")
                return syscall_info

            if not self.check_rate_limit(syscall_info['pid'], syscall_info['name']):
                syscall_info['blocked'] = True
                self.violation_counts[syscall_info['pid']] += 1
                self.logger.warning(f"Rate limit exceeded for {syscall_info['name']} by pid {syscall_info['pid']}")
                return syscall_info

            if self.detect_privilege_escalation(syscall_info):
                syscall_info['security_alert'] = 'privilege_escalation'

            # Monitor resource usage
            try:
                proc = psutil.Process(syscall_info['pid'])
                syscall_info['resource_usage'] = {
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'num_threads': proc.num_threads(),
                    'open_files': len(proc.open_files()),
                    'connections': len(proc.connections())
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            return syscall_info

        except Exception as e:
            self.logger.error(f"Error getting syscall info: {e}")
            return {}

    def check_permissions(self) -> bool:
        """Check if we have the necessary permissions"""
        if os.geteuid() != 0:
            self.logger.error("Application must be run with root privileges")
            return False
            
        # Check if DTrace is available on macOS
        if sys.platform == 'darwin':
            try:
                result = subprocess.run(['dtrace', '-l'], capture_output=True, text=True)
                return result.returncode == 0
            except Exception as e:
                self.logger.error(f"Failed to check DTrace availability: {e}")
                return False
                
        return True

    def attach_process(self, pid: int) -> bool:
        """
        Attach to a process for monitoring its system calls
        Returns True if successful, False otherwise
        """
        if not self.check_permissions():
            return False
            
        try:
            if pid in self.monitored_processes:
                return True

            # Check if process is still running
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    self.logger.error(f"Process {pid} is not running")
                    return False
                    
                # Store process info
                self.process_states[pid] = {
                    'name': proc.name(),
                    'create_time': proc.create_time(),
                    'status': proc.status()
                }
                
            except psutil.NoSuchProcess:
                self.logger.error(f"Process {pid} does not exist")
                return False
            except psutil.AccessDenied:
                self.logger.error(f"Access denied to process {pid}")
                return False

            # Use DTrace for syscall monitoring on macOS
            if sys.platform == 'darwin':
                dtrace_script = f"""
                syscall:::entry
                /pid == {pid}/
                {{
                    printf("%d,%s,%d\\n", pid, probefunc, timestamp);
                }}
                """
                
                # Create a temporary DTrace script
                script_path = Path('temp_dtrace.d')
                script_path.write_text(dtrace_script)
                
                # Start DTrace process
                self.dtrace_process = subprocess.Popen(
                    ['sudo', 'dtrace', '-s', str(script_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                
                # Start thread to read DTrace output
                threading.Thread(target=self._monitor_dtrace_output, daemon=True).start()
                
                self.monitored_processes[pid] = proc
                self.logger.info(f"Successfully attached to process {pid} ({self.process_states[pid]['name']})")
                return True
                
            return False

        except Exception as e:
            self.logger.error(f"Critical error in attach_process for {pid}: {e}")
            return False
            
    def _monitor_dtrace_output(self):
        """Monitor DTrace output and process syscalls"""
        while self.running and self.dtrace_process:
            line = self.dtrace_process.stdout.readline()
            if not line:
                break
                
            try:
                # Enhanced DTrace script output parsing
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    pid, syscall, timestamp = parts[:3]
                    
                    # Get process info
                    try:
                        proc = psutil.Process(int(pid))
                        proc_info = {
                            'name': proc.name(),
                            'username': proc.username(),
                            'cmdline': ' '.join(proc.cmdline()),
                            'cpu_percent': proc.cpu_percent(),
                            'memory_percent': proc.memory_percent(),
                            'status': proc.status()
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info = {}
                    
                    # Create detailed syscall info
                    syscall_info = {
                        'time': datetime.now().strftime('%H:%M:%S.%f'),
                        'pid': int(pid),
                        'name': syscall,
                        'timestamp': int(timestamp),
                        'status': 'completed',
                        'process_info': proc_info,
                        'risk_level': 'high' if syscall in self.HIGH_RISK_SYSCALLS else 'low',
                        'category': self._categorize_syscall(syscall)
                    }
                    
                    if self.callback:
                        self.event_queue.put(syscall_info)
                    
            except Exception as e:
                self.logger.error(f"Error processing DTrace output: {e}")
                
    def _categorize_syscall(self, syscall_name: str) -> str:
        """Categorize system calls for better organization"""
        categories = {
            'file_ops': {'open', 'read', 'write', 'close', 'unlink', 'rename', 'mkdir', 'rmdir'},
            'process_mgmt': {'fork', 'execve', 'clone', 'exit', 'wait4'},
            'network': {'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv'},
            'memory': {'mmap', 'munmap', 'brk', 'mprotect'},
            'security': {'chmod', 'chown', 'setuid', 'setgid', 'capset'},
            'ipc': {'pipe', 'socket', 'msgget', 'semget', 'shmget'}
        }
        
        for category, syscalls in categories.items():
            if syscall_name in syscalls:
                return category
        return 'other'

    def set_callback(self, callback: Callable):
        """Set callback function for system call events"""
        self.callback = callback
    
    def detach_process(self, pid: int) -> bool:
        """Detach from a monitored process"""
        try:
            if pid in self.monitored_processes:
                del self.monitored_processes[pid]
                self.logger.info(f"Detached from process {pid}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error detaching from process {pid}: {e}")
            return False
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.dtrace_process:
            self.dtrace_process.terminate()
            self.dtrace_process = None
        
        # Clean up temporary DTrace script
        try:
            Path('temp_dtrace.d').unlink()
        except:
            pass
        
        self.logger.info("Stopped system call monitoring")
    
    def get_available_processes(self) -> List[Dict[str, Any]]:
        """Get list of available processes that can be monitored"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                pinfo = proc.info
                # On macOS, filter out system processes and focus on user processes
                if sys.platform == 'darwin':
                    if (pinfo['username'] == os.getlogin() or  # User's processes
                        os.geteuid() == 0):                    # Or if we're root
                        processes.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'username': pinfo['username']
                        })
                else:
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def save_logs(self, output_dir: str = "logs"):
        """Save the collected syscall logs to a PDF file with timestamp"""
        try:
            # Create logs directory if it doesn't exist
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"syscall_logs_{timestamp}.pdf"
            filepath = Path(output_dir) / filename
            
            # Create PDF
            c = canvas.Canvas(str(filepath), pagesize=letter)
            width, height = letter
            
            # Add title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, height - 50, "System Call Monitor Logs")
            
            # Add timestamp
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Add monitoring duration
            if self.start_time and self.stop_time:
                duration = self.stop_time - self.start_time
                c.drawString(50, height - 90, f"Monitoring Duration: {duration}")
            
            # Add line separator
            c.line(50, height - 110, width - 50, height - 110)
            
            # Add syscall statistics
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, height - 130, "System Call Statistics")
            
            # Calculate statistics
            total_calls = sum(self.syscall_counts.values())
            stats_y = height - 160
            
            # Add statistics table
            for category, calls in self.syscall_counts.items():
                c.setFont("Helvetica", 12)
                c.drawString(60, stats_y, f"{category}: {calls} calls ({(calls/total_calls*100):.1f}%)")
                stats_y -= 20
            
            # Add line separator
            c.line(50, stats_y - 20, width - 50, stats_y - 20)
            
            # Add syscall logs
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, stats_y - 40, "System Call Logs")
            
            # Add logs
            log_y = stats_y - 70
            for pid, calls in self.syscall_logs.items():
                if log_y < 50:  # Start new page if needed
                    c.showPage()
                    log_y = height - 50
                
                c.setFont("Helvetica-Bold", 12)
                c.drawString(60, log_y, f"Process ID: {pid}")
                log_y -= 20
                
                for call in calls:
                    if log_y < 50:  # Start new page if needed
                        c.showPage()
                        log_y = height - 50
                    
                    c.setFont("Helvetica", 10)
                    c.drawString(70, log_y, f"- {call['name']}: {call.get('arguments', {}).get('arg', '')}")
                    log_y -= 15
            
            # Save PDF
            c.save()
            
            return str(filepath)
        except Exception as e:
            self.logger.error(f"Error saving logs: {str(e)}")
            return None

    def export_logs(self):
        """Export logs to PDF and optionally JSON format"""
        if not self.monitored_processes:
            self.logger.warning("No monitored processes to export logs.")
            return

        # Gather log details
        log_details = []
        for pid, logs in self.syscall_logs.items():
            for log in logs:
                log_details.append(log)

        # Define PDF file name
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        pdf_filename = f'monitoring_logs_{timestamp}.pdf'

        # Create PDF
        try:
            c = canvas.Canvas(pdf_filename, pagesize=letter)
            c.drawString(100, 750, "Monitoring Logs Report")
            c.drawString(100, 730, f"Monitoring Started: {self.start_time}")
            c.drawString(100, 710, f"Monitoring Stopped: {self.stop_time}")
            c.drawString(100, 690, "Log Details:")

            y = 670
            for detail in log_details:
                c.drawString(100, y, f"{detail}")
                y -= 20

            c.save()
            self.logger.info(f"Logs exported to {pdf_filename}")
        except Exception as e:
            self.logger.error(f"Failed to export logs: {e}")

        # Optionally save logs in JSON format
        json_filename = f'monitoring_logs_{timestamp}.json'
        try:
            with open(json_filename, 'w') as json_file:
                json.dump(log_details, json_file)
            self.logger.info(f"Logs exported to {json_filename}")
        except Exception as e:
            self.logger.error(f"Failed to export logs to JSON: {e}")
