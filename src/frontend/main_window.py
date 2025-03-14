from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QHBoxLayout, QStatusBar, QListWidget, QListWidgetItem,
    QSplitter, QDialog, QDialogButtonBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer
from src.monitor.syscall_monitor import SyscallMonitor
from src.security.security_validator import SecurityValidator
import psutil
from typing import Dict, Any
from datetime import datetime

class ProcessSelectionDialog(QDialog):
    def __init__(self, processes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Processes to Monitor")
        self.setGeometry(200, 200, 400, 500)
        
        layout = QVBoxLayout(self)
        
        # Process list
        self.process_list = QListWidget()
        for proc in processes:
            item = QListWidgetItem(f"{proc['name']} (PID: {proc['pid']}) - {proc['username']}")
            item.setData(Qt.ItemDataRole.UserRole, proc)
            self.process_list.addItem(item)
        
        layout.addWidget(self.process_list)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def get_selected_processes(self):
        """Get list of selected processes"""
        selected = []
        for item in self.process_list.selectedItems():
            selected.append(item.data(Qt.ItemDataRole.UserRole))
        return selected

class SystemCallInterface(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Call Interface")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize components
        self.monitor = SyscallMonitor()
        self.validator = SecurityValidator()
        self.monitored_processes = {}
        self.setup_ui()
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_syscall_table)
        self.update_timer.start(100)  # Update every 100ms
    
    def setup_ui(self):
        """Initialize the user interface"""
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Add header
        header = QLabel("System Call Monitor")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Add control buttons
        button_layout = QHBoxLayout()
        self.select_button = QPushButton("Select Processes")
        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.select_button)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Create splitter for tables
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Add system call table
        self.syscall_table = QTableWidget()
        self.syscall_table.setColumnCount(6)
        self.syscall_table.setHorizontalHeaderLabels([
            "Time", "Process", "System Call", "Status", "Risk Level", "Security Status"
        ])
        self.syscall_table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.syscall_table)
        
        # Add monitored processes table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(3)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Process Name", "Username"
        ])
        self.process_table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.process_table)
        
        layout.addWidget(splitter)
        
        # Connect signals
        self.select_button.clicked.connect(self.select_processes)
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        
        # Set callback for syscall events
        self.monitor.set_callback(self.handle_syscall)
    
    def select_processes(self):
        """Open process selection dialog"""
        processes = self.monitor.get_available_processes()
        dialog = ProcessSelectionDialog(processes, self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = dialog.get_selected_processes()
            self.monitored_processes = {
                proc['pid']: proc for proc in selected
            }
            self.update_process_table()
            self.status_bar.showMessage(f"Selected {len(selected)} processes")
    
    def update_process_table(self):
        """Update the process table with monitored processes"""
        self.process_table.setRowCount(0)
        for proc in self.monitored_processes.values():
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(row, 2, QTableWidgetItem(proc['username']))
    
    def handle_syscall(self, syscall_info: Dict[str, Any]):
        """Handle system call event"""
        pid = syscall_info['pid']
        if pid in self.monitored_processes:
            process_info = self.monitored_processes[pid]
            validation = self.validator.validate_syscall(syscall_info, process_info)
            
            row = self.syscall_table.rowCount()
            self.syscall_table.insertRow(row)
            
            self.syscall_table.setItem(row, 0, QTableWidgetItem(syscall_info['time']))
            self.syscall_table.setItem(row, 1, QTableWidgetItem(f"{process_info['name']} ({pid})"))
            self.syscall_table.setItem(row, 2, QTableWidgetItem(syscall_info['name']))
            self.syscall_table.setItem(row, 3, QTableWidgetItem(syscall_info['status']))
            self.syscall_table.setItem(row, 4, QTableWidgetItem(validation['risk_level']))
            
            security_status = "✓ Allowed" if validation['allowed'] else "⚠ Blocked"
            status_item = QTableWidgetItem(security_status)
            status_item.setToolTip("\n".join(validation['warnings']))
            self.syscall_table.setItem(row, 5, status_item)
            
            # Scroll to bottom
            self.syscall_table.scrollToBottom()
    
    def update_syscall_table(self):
        """Update syscall table with queued events"""
        while not self.monitor.event_queue.empty():
            syscall_info = self.monitor.event_queue.get()
            self.handle_syscall(syscall_info)
    
    def start_monitoring(self):
        """Start system call monitoring"""
        if not self.monitored_processes:
            QMessageBox.warning(self, "Warning", "Please select processes to monitor first.")
            return
            
        for pid in self.monitored_processes:
            self.monitor.attach_process(pid)
        
        self.monitor.start_monitoring()
        self.start_button.setEnabled(False)
        self.select_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage("Monitoring system calls...")
    
    def stop_monitoring(self):
        """Stop system call monitoring"""
        self.monitor.stop_monitoring()
        self.start_button.setEnabled(True)
        self.select_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Monitoring stopped")
    
    def closeEvent(self, event):
        """Handle window close event"""
        self.monitor.stop_monitoring()
        event.accept()
