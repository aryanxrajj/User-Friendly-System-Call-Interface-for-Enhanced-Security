import psutil
from ptrace import PtraceError
from ptrace.debugger import PtraceDebugger, ProcessSignal
from typing import Dict, Any, List, Optional, Callable
import logging
from datetime import datetime
from queue import Queue
import threading
import time

class SyscallMonitor:
    def __init__(self):
        self.debugger = PtraceDebugger()
        self.monitored_processes: Dict[int, Any] = {}
        self.running = False
        self.callback: Optional[Callable] = None
        self.event_queue = Queue()
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging for system call monitoring"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='syscall_monitor.log'
        )
        self.logger = logging.getLogger(__name__)
    
    def set_callback(self, callback: Callable):
        """Set callback function for system call events"""
        self.callback = callback
    
    def attach_process(self, pid: int) -> bool:
        """
        Attach to a process for monitoring its system calls
        Returns True if successful, False otherwise
        """
        try:
            if pid in self.monitored_processes:
                return True
                
            process = self.debugger.addProcess(pid, True)
            self.monitored_processes[pid] = process
            self.logger.info(f"Attached to process {pid}")
            return True
        except PtraceError as e:
            self.logger.error(f"Failed to attach to process {pid}: {e}")
            return False
    
    def detach_process(self, pid: int) -> bool:
        """Detach from a monitored process"""
        try:
            if pid in self.monitored_processes:
                process = self.monitored_processes[pid]
                process.detach()
                del self.monitored_processes[pid]
                self.logger.info(f"Detached from process {pid}")
                return True
            return False
        except PtraceError as e:
            self.logger.error(f"Failed to detach from process {pid}: {e}")
            return False
    
    def get_syscall_info(self, process) -> Dict[str, Any]:
        """Get information about the current system call for a monitored process"""
        try:
            syscall = process.getCurrentSyscall()
            return {
                'time': datetime.now().strftime('%H:%M:%S.%f'),
                'pid': process.pid,
                'name': syscall.name if syscall else "unknown",
                'arguments': syscall.arguments if syscall else [],
                'result': syscall.result if syscall else None,
                'status': 'completed' if syscall and syscall.result is not None else 'in_progress'
            }
        except Exception as e:
            self.logger.error(f"Error getting syscall info: {e}")
            return {}
    
    def _monitor_thread(self):
        """Thread function to monitor system calls"""
        while self.running:
            try:
                for pid, process in list(self.monitored_processes.items()):
                    if not process.is_attached:
                        continue
                        
                    process.cont()
                    event = process.waitEvent()
                    
                    if event is None or isinstance(event, ProcessSignal):
                        continue
                        
                    syscall_info = self.get_syscall_info(process)
                    if syscall_info and self.callback:
                        self.event_queue.put(syscall_info)
                        
            except Exception as e:
                self.logger.error(f"Error in monitor thread: {e}")
                time.sleep(0.1)
    
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_thread)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("Started system call monitoring")
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1.0)
        for pid in list(self.monitored_processes.keys()):
            self.detach_process(pid)
        self.logger.info("Stopped system call monitoring")
    
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
