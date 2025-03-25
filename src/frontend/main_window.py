from PyQt6.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, 
    QPushButton, QTableWidget, QTableWidgetItem, QLabel,
    QHBoxLayout, QStatusBar, QListWidget, QListWidgetItem,
    QSplitter, QDialog, QDialogButtonBox, QMessageBox, QHeaderView,
    QLineEdit, QFormLayout, QToolBar, QFrame, QProgressBar,
    QInputDialog
)
from PyQt6.QtCore import Qt, QTimer, QEasingCurve, QPropertyAnimation, QRect
from PyQt6.QtGui import QFont, QColor, QPainter, QPalette
from src.monitor.syscall_monitor import SyscallMonitor
from src.security.security_validator import SecurityValidator
from src.security.auth import AuthManager
from .monitoring_reason_dialog import MonitoringReasonDialog
import psutil
from typing import Dict, Any
from datetime import datetime
from collections import defaultdict
import logging
import os

class LoginDialog(QDialog):
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setup_ui()
        self.setup_animations()
        
    def setup_ui(self):
        self.setWindowTitle("System Call Interface - Login")
        self.setFixedSize(400, 500)
        
        # Main layout
        layout = QVBoxLayout()
        
        # Title with animation
        self.title = QLabel("System Call Interface")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setFont(QFont("Courier New", 24, QFont.Weight.Bold))
        self.title.setStyleSheet("""
            QLabel {
                color: #00ff00;
                background-color: #1e1e1e;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 30px;
            }
        """)
        layout.addWidget(self.title)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        
        # Username field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #00ff00;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
            QLineEdit:focus {
                border-color: #00cc00;
            }
        """)
        form_layout.addRow("Username:", self.username_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #00ff00;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
            QLineEdit:focus {
                border-color: #00cc00;
            }
        """)
        form_layout.addRow("Password:", self.password_input)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #002200;
                color: #ffffff;
                border: 2px solid #00ff00;
                border-radius: 10px;
                padding: 12px 24px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #004400;
            }
            QPushButton:pressed {
                background-color: #002200;
            }
        """)
        self.login_button.clicked.connect(self.attempt_login)
        
        # Add form to layout
        self.form_container = QWidget()
        self.form_container.setLayout(form_layout)
        self.form_container.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        layout.addWidget(self.form_container, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Progress bar for login animation
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e1e1e;
                border: 2px solid #00ff00;
                border-radius: 5px;
                text-align: center;
                min-height: 15px;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.progress_bar, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Add login button to layout
        button_container = QWidget()
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.login_button)
        button_layout.addStretch()
        button_container.setLayout(button_layout)
        layout.addWidget(button_container)
        
        self.setLayout(layout)
        
        # Set window background
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
            }
        """)
        
    def setup_animations(self):
        # Title animation
        self.title_animation = QPropertyAnimation(self.title, b"geometry")
        self.title_animation.setDuration(1000)
        self.title_animation.setEasingCurve(QEasingCurve.Type.OutBounce)
        
        # Form container animation
        self.form_animation = QPropertyAnimation(self.form_container, b"geometry")
        self.form_animation.setDuration(800)
        self.form_animation.setEasingCurve(QEasingCurve.Type.OutElastic)
        
    def start_animations(self):
        # Title animation
        title_rect = self.title.geometry()
        self.title_animation.setStartValue(QRect(title_rect.x(), -title_rect.height(), 
                                               title_rect.width(), title_rect.height()))
        self.title_animation.setEndValue(QRect(title_rect.x(), title_rect.y(), 
                                              title_rect.width(), title_rect.height()))
        self.title_animation.start()
        
        # Form animation
        form_rect = self.form_container.geometry()
        self.form_animation.setStartValue(QRect(form_rect.x(), form_rect.y() + 50, 
                                               form_rect.width(), form_rect.height()))
        self.form_animation.setEndValue(QRect(form_rect.x(), form_rect.y(), 
                                            form_rect.width(), form_rect.height()))
        self.form_animation.start()
        
    def attempt_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Please enter both username and password.")
            return
            
        # Show progress bar
        self.progress_bar.setVisible(True)
        self.login_button.setEnabled(False)
        
        # Start progress animation
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(50)
        
        # Attempt login immediately
        self.process_login(username, password)
        
    def update_progress(self):
        value = self.progress_bar.value()
        if value < 100:
            self.progress_bar.setValue(value + 5)
        else:
            self.progress_timer.stop()
            
    def process_login(self, username: str, password: str):
        """Process the login attempt"""
        try:
            # Show loading message
            QMessageBox.information(self, "Login", "Verifying credentials...")
            
            # Attempt authentication
            if self.auth_manager.authenticate(username, password):
                # Show success message
                QMessageBox.information(self, "Success", "Login successful!")
                self.accept()
            else:
                # Show error message
                QMessageBox.warning(self, "Login Error", "Invalid username or password.")
                self.progress_bar.setVisible(False)
                self.login_button.setEnabled(True)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")
            self.progress_bar.setVisible(False)
            self.login_button.setEnabled(True)

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
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize security components
        self.current_user = None  # Initialize current_user attribute
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
        
        # Initialize syscall statistics
        self.syscall_counts = defaultdict(int)
        self.last_update_time = datetime.now()

    def setup_default_admin(self):
        """Create default admin user if not exists"""
        try:
            if not self.auth_manager.authenticate("admin", "admin123"):
                self.auth_manager.create_user("admin", "admin123", "admin")
            self.logger.info("Default admin user setup completed")
        except Exception as e:
            self.logger.error(f"Failed to setup default admin: {e}")
            raise

    def authenticate_user(self):
        """Authenticate user and show login dialog"""
        try:
            dialog = LoginDialog(self.auth_manager, self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.logger.info("User authenticated successfully")
                return True
            else:
                self.logger.info("User cancelled login")
                return False
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            QMessageBox.critical(self, "Error", f"Failed to authenticate: {str(e)}")
            return False

    def setup_ui(self):
        """Initialize the user interface"""
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        
        # Set window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            
            QLabel {
                color: #ffffff;
                font-family: 'Courier New', monospace;
            }
            
            #HeadingLabel {
                background-color: #002200;
                border: 2px solid #00ff00;
                color: #ffffff;
                border-radius: 10px;
                padding: 15px 30px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
                font-size: 28px;
                margin: 20px;
                box-shadow: 0 2px 4px rgba(0, 255, 0, 0.2);
                text-shadow: 2px 2px #002200;
            }
            
            #HeadingLabel:hover {
                background-color: #004400;
                border-color: #00cc00;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0, 255, 0, 0.3);
            }
            
            QPushButton {
                background-color: #002200;
                border: 2px solid #00ff00;
                color: #ffffff;
                border-radius: 10px;
                padding: 12px 24px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 2px 4px rgba(0, 255, 0, 0.2);
            }
            
            QPushButton:hover {
                background-color: #004400;
                border-color: #00cc00;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0, 255, 0, 0.3);
            }
            
            QPushButton:pressed {
                background-color: #002200;
                transform: translateY(0);
                box-shadow: 0 2px 4px rgba(0, 255, 0, 0.2);
            }
            
            QPushButton:disabled {
                background-color: #1e1e1e;
                border-color: #004400;
                color: #ffffff;
                cursor: not-allowed;
            }
            
            QTableWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #00ff00;
                font-family: 'Courier New', monospace;
                border-radius: 8px;
            }
            
            QHeaderView::section {
                background-color: #002200;
                color: #ffffff;
                padding: 4px;
                border: 1px solid #00ff00;
                border-radius: 4px;
            }
            
            QStatusBar {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Courier New', monospace;
                border-top: 1px solid #00ff00;
            }
            
            QSplitter::handle {
                background-color: #00ff00;
                border-radius: 2px;
            }
        """)
        
        # Main layout
        main_layout = QVBoxLayout(self.main_widget)
        main_layout.setSpacing(20)
        
        # Add heading at the top
        header = QLabel("System Call Monitor")
        header.setObjectName("HeadingLabel")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header)
        
        # Create toolbar below heading with spacing
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        toolbar.setContentsMargins(20, 0, 20, 0)
        
        # Add process selection button with animation
        self.select_button = QPushButton("Select Processes")
        self.select_button.clicked.connect(self.select_processes)
        self.select_button.setMinimumWidth(150)
        self.select_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.select_button)
        
        # Add start/stop monitoring button with animation
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        self.start_button.setMinimumWidth(150)
        self.start_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.start_button)
        
        # Add save logs button with animation
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self.save_logs)
        self.save_logs_button.setMinimumWidth(120)
        self.save_logs_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.save_logs_button)
        
        # Add clear data button with animation
        self.clear_button = QPushButton("Clear Data")
        self.clear_button.clicked.connect(self.clear_data)
        self.clear_button.setMinimumWidth(120)
        self.clear_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.clear_button)
        
        # Add stop monitoring button with animation
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        self.stop_button.setMinimumWidth(150)
        self.stop_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.stop_button)
        
        # Add terminate process button with animation
        self.terminate_button = QPushButton("Terminate Process")
        self.terminate_button.clicked.connect(self.terminate_process)
        self.terminate_button.setMinimumWidth(150)
        self.terminate_button.setStyleSheet("border-radius: 10px;")
        toolbar.addWidget(self.terminate_button)
        
        # Add toolbar to main layout
        main_layout.addLayout(toolbar)
        
        # Create splitter for tables
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #00ff00;
            }
        """)
        
        # Process table
        process_widget = QWidget()
        process_layout = QVBoxLayout(process_widget)
        process_layout.setContentsMargins(10, 10, 10, 10)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(3)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "Status"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        process_layout.addWidget(self.process_table)
        splitter.addWidget(process_widget)
        
        # Syscall table
        syscall_widget = QWidget()
        syscall_layout = QVBoxLayout(syscall_widget)
        syscall_layout.setContentsMargins(10, 10, 10, 10)
        
        self.syscall_table = QTableWidget()
        self.syscall_table.setColumnCount(4)
        self.syscall_table.setHorizontalHeaderLabels(["PID", "System Call", "Arguments", "Timestamp"])
        self.syscall_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        syscall_layout.addWidget(self.syscall_table)
        splitter.addWidget(syscall_widget)
        
        # Statistics table
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        stats_layout.setContentsMargins(10, 10, 10, 10)
        
        self.syscall_stats = QTableWidget()
        self.syscall_stats.setColumnCount(2)
        self.syscall_stats.setHorizontalHeaderLabels(["System Call", "Count"])
        self.syscall_stats.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        stats_layout.addWidget(self.syscall_stats)
        splitter.addWidget(stats_widget)
        
        main_layout.addWidget(splitter)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #002200;
                color: #ffffff;
                border-top: 1px solid #00ff00;
            }
        """)
        self.status_bar.showMessage("Ready")
        
        # Connect signals
        self.monitor.set_callback(self.handle_syscall)
    
    def clear_data(self):
        """Clear all displayed data"""
        self.syscall_table.setRowCount(0)
        self.process_table.setRowCount(0)
        self.syscall_stats.setRowCount(0)
        self.syscall_counts.clear()
        self.status_bar.showMessage("Data cleared")
        
    def update_statistics(self, syscall_info: Dict[str, Any]):
        """Update the syscall statistics table"""
        try:
            # Update syscall count
            syscall_name = syscall_info['name']
            self.syscall_counts[syscall_name] += 1
            
            # Update statistics table
            self.syscall_stats.setRowCount(0)
            
            # Sort syscalls by count in descending order
            sorted_syscalls = sorted(
                self.syscall_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            # Add top 10 syscalls to table
            for i, (syscall, count) in enumerate(sorted_syscalls[:10]):
                self.syscall_stats.insertRow(i)
                self.syscall_stats.setItem(i, 0, QTableWidgetItem(syscall))
                count_item = QTableWidgetItem(str(count))
                count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight)
                self.syscall_stats.setItem(i, 1, count_item)
            
            # Update status bar with total syscalls
            total_syscalls = sum(self.syscall_counts.values())
            self.status_bar.showMessage(f"Total syscalls: {total_syscalls}")
            
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def handle_syscall(self, syscall_info: Dict[str, Any]):
        """Handle system call with enhanced security validation"""
        try:
            if syscall_info is None:
                self.logger.error("Received None for syscall_info")
                return
            if 'pid' not in syscall_info:
                self.logger.error("syscall_info does not contain 'pid'")
                return

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
            self.logger.error(f"Error handling syscall: {e}")
    
    def add_syscall_entry(self, syscall_info: Dict[str, Any]):
        """Add system call entry to table"""
        row = self.syscall_table.rowCount()
        self.syscall_table.insertRow(row)
        
        # Basic info
        self.syscall_table.setItem(row, 0, QTableWidgetItem(syscall_info['time']))
        self.syscall_table.setItem(row, 1, QTableWidgetItem(f"{syscall_info['process_info']['name']} ({syscall_info['pid']})"))
        self.syscall_table.setItem(row, 2, QTableWidgetItem(syscall_info['name']))
        self.syscall_table.setItem(row, 3, QTableWidgetItem(syscall_info.get('category', 'other')))
        
        # Resource usage
        self.syscall_table.setItem(row, 4, QTableWidgetItem(f"{syscall_info['process_info'].get('cpu_percent', 0):.1f}"))
        self.syscall_table.setItem(row, 5, QTableWidgetItem(f"{syscall_info['process_info'].get('memory_percent', 0):.1f}"))
        
        # Risk level with color coding
        risk_item = QTableWidgetItem(syscall_info.get('risk_level', 'low'))
        if syscall_info.get('risk_level') == 'high':
            risk_item.setBackground(QColor(255, 200, 200)) # Light red for high risk
        self.syscall_table.setItem(row, 6, risk_item)
        
        # Additional details
        details = []
        if syscall_info['process_info'].get('cmdline'):
            details.append(f"Command: {syscall_info['process_info']['cmdline']}")
        if syscall_info['process_info'].get('username'):
            details.append(f"User: {syscall_info['process_info']['username']}")
        self.syscall_table.setItem(row, 7, QTableWidgetItem(' | '.join(details)))
        
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
        self.process_table.setRowCount(0)
        for proc in self.monitored_processes.values():
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(row, 2, QTableWidgetItem(proc['username']))
    
    def start_monitoring(self):
        """Start monitoring system calls with reason"""
        if self.is_monitoring:
            QMessageBox.warning(self, "Monitoring", "Monitoring is already active.")
            return
            
        if not self.monitored_processes:
            QMessageBox.warning(
                self,
                "No Processes Selected",
                "Please select at least one process to monitor."
            )
            return
            
        # Show reason dialog with selected processes
        dialog = MonitoringReasonDialog(self, list(self.monitored_processes.keys()))
        if dialog.exec() == QDialog.DialogCode.Accepted:
            reason = dialog.get_reason()
            if not reason:
                QMessageBox.warning(self, "Warning", "Please provide a reason for monitoring.")
                return
                
            # Save the reason to file
            filepath = dialog.save_reason(reason)
            if filepath:
                self.logger.info(f"Monitoring reason saved to: {filepath}")
                
                # Start monitoring
                try:
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

        else:
            self.logger.info("Monitoring cancelled by user")

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
            if not self.is_monitoring:
                return
                
            self.logger.info("Stopping monitoring")
            self.monitor.stop()
            self.is_monitoring = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.select_button.setEnabled(True)
            self.update_process_table()  
            
            # Check if there are any monitored processes left
            if not self.monitored_processes:
                QMessageBox.information(
                    self,
                    "Monitoring Stopped",
                    "All monitored processes have terminated."
                )
                return
            
            self.logger.info("Monitoring stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to stop monitoring: {str(e)}"
            )
            self.logger.debug("Stopping monitoring failed, application may close unexpectedly.")

    def save_logs(self):
        """Save the current syscall logs to a PDF file"""
        try:
            filepath = self.monitor.save_logs()
            if filepath:
                QMessageBox.information(
                    self,
                    "Logs Saved",
                    f"Logs have been saved to: {filepath}"
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to save logs: {str(e)}"
            )

    def terminate_process(self):
        """Terminate the selected process and log the reason."""
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Process Selected", "Please select a process to terminate.")
            return
        
        try:
            pid = int(selected_items[0].text())  # Assuming PID is in the first column
        except ValueError:
            QMessageBox.warning(self, "Invalid PID", "The selected process does not have a valid PID.")
            return
        
        reason, ok = QInputDialog.getText(self, "Terminate Process", "Enter reason for termination:")
        if ok and reason:
            if self.monitor.terminate_process(pid, reason):
                QMessageBox.information(self, "Process Terminated", f"Process {pid} has been terminated.")
            else:
                QMessageBox.critical(self, "Error", "Failed to terminate the process.")
        else:
            QMessageBox.warning(self, "No Reason Provided", "Please provide a reason for termination.")

    def closeEvent(self, event):
        """Handle application close event"""
        try:
            if self.is_monitoring:
                self.stop_monitoring()
            event.accept()
        except Exception as e:
            self.logger.error(f"Error during close: {e}")
            event.accept() # Still close even if there's an error