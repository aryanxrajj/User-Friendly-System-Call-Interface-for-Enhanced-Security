from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QHBoxLayout, QStatusBar, QListWidget, QListWidgetItem,
    QSplitter, QDialog, QDialogButtonBox, QMessageBox, QHeaderView,
    QLineEdit, QFormLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from src.monitor.syscall_monitor import SyscallMonitor
from src.security.security_validator import SecurityValidator
from src.security.auth import AuthManager
import psutil
from typing import Dict, Any
from datetime import datetime
from collections import defaultdict

class LoginDialog(QDialog):
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setWindowTitle("Login")
        self.setModal(True)
        
        self.setFixedSize(300, 200)
        self.setStyleSheet("""
            QDialog {
                background-color: #000000;
                border: 1px solid #00FF00;
                border-radius: 10px;
            }
            QLabel, QPushButton, QLineEdit {
                color: #00FF00;
                font-family: 'Courier New', monospace;
                font-weight: bold;
            }
            QLineEdit {
                background-color: #000000;
                border: 1px solid #00FF00;
            }
            QPushButton {
                background-color: #000000;
                border: 1px solid #00FF00;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #004400;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        
        form.addRow("Username:", self.username)
        form.addRow("Password:", self.password)
        layout.addLayout(form)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.try_login)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.token = None
    
    def try_login(self):
        username = self.username.text()
        password = self.password.text()
        
        token = self.auth_manager.authenticate(username, password)
        if token:
            self.token = token
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password")

class ProcessSelectionDialog(QDialog):
    def __init__(self, processes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Processes to Monitor")
        self.setGeometry(200, 200, 400, 500)
        
        layout = QVBoxLayout(self)
        
        # Add search bar for processes
        self.process_search_bar = QLineEdit()
        self.process_search_bar.setPlaceholderText("Search processes...")
        layout.addWidget(self.process_search_bar)
        
        # Connect search bar signal to filter function
        self.process_search_bar.textChanged.connect(self.filter_processes)
        
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
    
    def filter_processes(self, text):
        """Filter processes based on input text"""
        for i in range(self.process_list.count()):
            item = self.process_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())
    
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
        
        # Initialize security components
        self.auth_manager = AuthManager()
        self.setup_default_admin()
        
        # Authenticate user before proceeding
        if not self.authenticate_user():
            self.close()
            return
            
        # Initialize components
        self.monitor = SyscallMonitor()
        self.validator = SecurityValidator()
        self.monitored_processes = {}
        
        # Check permissions
        if not self.monitor.check_permissions():
            QMessageBox.critical(
                self,
                "Permission Error",
                "This application requires root privileges to monitor system calls.\n"
                "Please run the application with sudo."
            )
            self.close()
            return
            
        self.setup_ui()
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_syscall_table)
        self.update_timer.start(100) # Update every 100ms
        
        # Keep track of monitoring state
        self.is_monitoring = False
    
    def setup_default_admin(self):
        """Create default admin user if not exists"""
        if not self.auth_manager.get_user_role("admin"):
            self.auth_manager.create_user("admin", "admin123", "admin")
            
    def authenticate_user(self) -> bool:
        """Show login dialog and authenticate user"""
        dialog = LoginDialog(self.auth_manager, self)
        if dialog.exec():
            self.current_user = self.auth_manager.verify_token(dialog.token)
            if self.current_user:
                self.auth_manager.log_action(
                    self.current_user["username"],
                    "app_access",
                    {"role": self.current_user["role"]}
                )
                return True
        return False

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
        self.clear_button = QPushButton("Clear Data")
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.select_button)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_button)
        layout.addLayout(button_layout)
        
        # Create splitter for tables
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Add system call table with enhanced columns
        self.syscall_table = QTableWidget()
        self.syscall_table.setColumnCount(9)
        self.syscall_table.setHorizontalHeaderLabels([
            "Time", "Process", "System Call", "Category", "Status",
            "CPU %", "Memory %", "Risk Level", "Details"
        ])
        
        # Set column widths
        header = self.syscall_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Process
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents) # System Call
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents) # Category
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents) # Status
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents) # CPU
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents) # Memory
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents) # Risk
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch) # Details
        
        splitter.addWidget(self.syscall_table)
        
        # Add statistics panel
        stats_widget = QWidget()
        stats_layout = QHBoxLayout(stats_widget)
        
        # Process statistics
        self.process_stats = QTableWidget()
        self.process_stats.setColumnCount(5)
        self.process_stats.setHorizontalHeaderLabels([
            "PID", "Process Name", "CPU %", "Memory %", "Status"
        ])
        self.process_stats.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # System call statistics
        self.syscall_stats = QTableWidget()
        self.syscall_stats.setColumnCount(3)
        self.syscall_stats.setHorizontalHeaderLabels([
            "Category", "Count", "Risk Distribution"
        ])
        self.syscall_stats.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        stats_layout.addWidget(self.process_stats)
        stats_layout.addWidget(self.syscall_stats)
        splitter.addWidget(stats_widget)
        
        layout.addWidget(splitter)
        
        # Connect signals
        self.select_button.clicked.connect(self.select_processes)
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.clear_button.clicked.connect(self.clear_data)
        #aryan
        # Set callback for syscall events
        self.monitor.set_callback(self.handle_syscall)
        
        # Initialize statistics
        self.syscall_counts = defaultdict(int)
        self.risk_counts = defaultdict(lambda: defaultdict(int))
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QLabel, QPushButton, QLineEdit {
                color: #00FF00;
                font-family: 'Courier New', monospace;
                font-weight: bold;
            }
            QLineEdit {
                background-color: #000000;
                border: 1px solid #00FF00;
            }
            QPushButton {
                background-color: #000000;
                border: 1px solid #00FF00;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #004400;
            }
            QTableWidget {
                background-color: #000000;
                color: #00FF00;
                gridline-color: #00FF00;
                font-family: 'Courier New', monospace;
            }
            QHeaderView::section {
                background-color: #000000;
                color: #00FF00;
                border: 1px solid #00FF00;
            }
        """)
    
    def clear_data(self):
        """Clear all displayed data"""
        self.syscall_table.setRowCount(0)
        self.process_stats.setRowCount(0)
        self.syscall_stats.setRowCount(0)
        self.syscall_counts.clear()
        self.risk_counts.clear()
        self.status_bar.showMessage("Data cleared")
        
    def update_statistics(self, syscall_info: Dict[str, Any]):
        """Update statistics tables with new syscall information"""
        # Update syscall counts
        category = syscall_info.get('category', 'other')
        self.syscall_counts[category] += 1
        self.risk_counts[category][syscall_info.get('risk_level', 'low')] += 1
        
        # Update process statistics
        pid = syscall_info['pid']
        proc_info = syscall_info.get('process_info', {})
        
        # Find existing row for this PID
        found = False
        for row in range(self.process_stats.rowCount()):
            if self.process_stats.item(row, 0).text() == str(pid):
                self.process_stats.setItem(row, 2, QTableWidgetItem(f"{proc_info.get('cpu_percent', 0):.1f}"))
                self.process_stats.setItem(row, 3, QTableWidgetItem(f"{proc_info.get('memory_percent', 0):.1f}"))
                self.process_stats.setItem(row, 4, QTableWidgetItem(proc_info.get('status', 'unknown')))
                found = True
                break
        
        # Add new row if PID not found
        if not found and proc_info:
            row = self.process_stats.rowCount()
            self.process_stats.insertRow(row)
            self.process_stats.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.process_stats.setItem(row, 1, QTableWidgetItem(proc_info.get('name', 'unknown')))
            self.process_stats.setItem(row, 2, QTableWidgetItem(f"{proc_info.get('cpu_percent', 0):.1f}"))
            self.process_stats.setItem(row, 3, QTableWidgetItem(f"{proc_info.get('memory_percent', 0):.1f}"))
            self.process_stats.setItem(row, 4, QTableWidgetItem(proc_info.get('status', 'unknown')))
        
        # Update syscall statistics
        self.syscall_stats.setRowCount(0)
        for category, count in self.syscall_counts.items():
            row = self.syscall_stats.rowCount()
            self.syscall_stats.insertRow(row)
            self.syscall_stats.setItem(row, 0, QTableWidgetItem(category))
            self.syscall_stats.setItem(row, 1, QTableWidgetItem(str(count)))
            
            # Calculate risk distribution
            total = sum(self.risk_counts[category].values())
            if total > 0:
                high_risk = self.risk_counts[category]['high']
                risk_pct = (high_risk / total) * 100
                risk_text = f"High Risk: {risk_pct:.1f}%"
            else:
                risk_text = "No data"
            self.syscall_stats.setItem(row, 2, QTableWidgetItem(risk_text))
            
    def handle_syscall(self, syscall_info: Dict[str, Any]):
        """Handle system call with enhanced security validation"""
        try:
            # Get process info
            proc = psutil.Process(syscall_info['pid'])
            process_info = {
                'name': proc.name(),
                'username': proc.username(),
                'cmdline': proc.cmdline()
            }
            
            # Validate syscall
            validation = self.validator.validate_syscall(syscall_info, process_info)
            
            # Log security events
            if validation['warnings']:
                self.auth_manager.log_action(
                    self.current_user["username"],
                    "security_warning",
                    {
                        "syscall": syscall_info['name'],
                        "warnings": validation['warnings'],
                        "process": process_info
                    }
                )
            
            # Update UI with validation results
            self.add_syscall_entry({
                **syscall_info,
                'validation': validation,
                'process_info': process_info
            })
            
        except Exception as e:
            print(f"Error handling syscall: {e}")
    
    def add_syscall_entry(self, syscall_info: Dict[str, Any]):
        """Add system call entry to table"""
        row = self.syscall_table.rowCount()
        self.syscall_table.insertRow(row)
        
        # Basic info
        self.syscall_table.setItem(row, 0, QTableWidgetItem(syscall_info['time']))
        self.syscall_table.setItem(row, 1, QTableWidgetItem(f"{syscall_info['process_info']['name']} ({syscall_info['pid']})"))
        self.syscall_table.setItem(row, 2, QTableWidgetItem(syscall_info['name']))
        self.syscall_table.setItem(row, 3, QTableWidgetItem(syscall_info.get('category', 'other')))
        self.syscall_table.setItem(row, 4, QTableWidgetItem(syscall_info['status']))
        
        # Resource usage
        self.syscall_table.setItem(row, 5, QTableWidgetItem(f"{syscall_info['process_info'].get('cpu_percent', 0):.1f}"))
        self.syscall_table.setItem(row, 6, QTableWidgetItem(f"{syscall_info['process_info'].get('memory_percent', 0):.1f}"))
        
        # Risk level with color coding
        risk_item = QTableWidgetItem(syscall_info.get('risk_level', 'low'))
        if syscall_info.get('risk_level') == 'high':
            risk_item.setBackground(QColor(255, 200, 200)) # Light red for high risk
        self.syscall_table.setItem(row, 7, risk_item)
        
        # Additional details
        details = []
        if syscall_info['process_info'].get('cmdline'):
            details.append(f"Command: {syscall_info['process_info']['cmdline']}")
        if syscall_info['process_info'].get('username'):
            details.append(f"User: {syscall_info['process_info']['username']}")
        self.syscall_table.setItem(row, 8, QTableWidgetItem(' | '.join(details)))
        
        # Update statistics
        self.update_statistics(syscall_info)
        
        # Scroll to bottom and ensure last row is visible
        self.syscall_table.scrollToBottom()
    
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
        self.process_stats.setRowCount(0)
        for proc in self.monitored_processes.values():
            row = self.process_stats.rowCount()
            self.process_stats.insertRow(row)
            self.process_stats.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_stats.setItem(row, 1, QTableWidgetItem(proc['name']))
            self.process_stats.setItem(row, 2, QTableWidgetItem(proc['username']))
    
    def start_monitoring(self):
        """Start monitoring selected processes"""
        try:
            if not self.monitored_processes:
                QMessageBox.warning(
                    self,
                    "No Processes Selected",
                    "Please select at least one process to monitor."
                )
                return

            self.is_monitoring = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.select_button.setEnabled(False)
            
            # Start monitoring each selected process
            for pid in self.monitored_processes.keys():
                try:
                    if not self.monitor.start_monitoring(pid):
                        raise Exception(f"Failed to start monitoring process {pid}")
                except Exception as e:
                    self.logger.error(f"Error monitoring process {pid}: {e}")
                    QMessageBox.warning(
                        self,
                        "Monitoring Error",
                        f"Failed to monitor process {pid}: {str(e)}"
                    )
                    continue

            self.status_bar.showMessage("Monitoring system calls...")
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to start monitoring: {str(e)}"
            )
            self.stop_monitoring()

    def update_syscall_table(self):
        """Update the syscall table with new entries"""
        try:
            if not self.is_monitoring:
                return

            # Update process statistics
            for pid in list(self.monitored_processes.keys()):
                try:
                    proc = psutil.Process(pid)
                    if not proc.is_running():
                        self.monitored_processes.pop(pid)
                        continue
                except psutil.NoSuchProcess:
                    self.monitored_processes.pop(pid)
                    continue
                except Exception as e:
                    self.logger.error(f"Error updating process stats: {e}")
                    continue

            # If no processes left to monitor, stop monitoring
            if not self.monitored_processes:
                self.stop_monitoring()
                QMessageBox.information(
                    self,
                    "Monitoring Stopped",
                    "All monitored processes have terminated."
                )
                return

        except Exception as e:
            self.logger.error(f"Error in update_syscall_table: {e}")

    def stop_monitoring(self):
        """Stop monitoring system calls"""
        try:
            self.monitor.stop()
            self.is_monitoring = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.select_button.setEnabled(True)
            self.status_bar.showMessage("Monitoring stopped")
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to stop monitoring: {str(e)}"
            )

    def closeEvent(self, event):
        """Handle application close event"""
        try:
            if self.is_monitoring:
                self.stop_monitoring()
            event.accept()
        except Exception as e:
            self.logger.error(f"Error during close: {e}")
            event.accept() # Still close even if there's an error