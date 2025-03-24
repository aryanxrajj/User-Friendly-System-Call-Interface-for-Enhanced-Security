from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QLabel, 
                             QTextEdit, QPushButton, QMessageBox)
from PyQt6.QtCore import Qt
from datetime import datetime
import os
import psutil

class MonitoringReasonDialog(QDialog):
    def __init__(self, parent=None, selected_processes=None):
        super().__init__(parent)
        self.setWindowTitle("Monitoring Reason")
        self.setMinimumWidth(600)
        self.selected_processes = selected_processes or []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Please provide a reason for monitoring:")
        title.setStyleSheet("""
            QLabel {
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-weight: bold;
                font-size: 14px;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Process details
        if self.selected_processes:
            details = QLabel("Processes to be monitored:")
            details.setStyleSheet("""
                QLabel {
                    color: #00ff00;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    margin-bottom: 10px;
                }
            """)
            layout.addWidget(details)
            
            for pid in self.selected_processes:
                try:
                    proc = psutil.Process(pid)
                    proc_info = QLabel(f"PID: {pid}, Name: {proc.name()}, User: {proc.username()}")
                    proc_info.setStyleSheet("""
                        QLabel {
                            color: #ffffff;
                            font-family: 'Courier New', monospace;
                            font-size: 11px;
                            margin-bottom: 5px;
                            padding: 5px;
                            border: 1px solid #00ff00;
                            border-radius: 4px;
                        }
                    """)
                    layout.addWidget(proc_info)
                except psutil.NoSuchProcess:
                    pass
            
            layout.addSpacing(15)
        
        # Text area for reason
        self.reason_text = QTextEdit()
        self.reason_text.setPlaceholderText("Enter your reason for monitoring these processes...")
        self.reason_text.setMinimumHeight(100)
        self.reason_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #00ff00;
                font-family: 'Courier New', monospace;
                padding: 10px;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.reason_text)
        
        # Submit button
        submit_btn = QPushButton("Submit")
        submit_btn.setStyleSheet("""
            QPushButton {
                background-color: #002200;
                border: 2px solid #00ff00;
                color: #ffffff;
                border-radius: 10px;
                padding: 10px 20px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #004400;
            }
        """)
        submit_btn.clicked.connect(self.accept)
        layout.addWidget(submit_btn)
        
        self.setLayout(layout)

    def get_reason(self):
        """Get the entered reason"""
        return self.reason_text.toPlainText().strip()

    def save_reason(self, reason):
        """Save the monitoring reason to a file with process details"""
        try:
            # Get the project root directory
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            # Create logs directory if it doesn't exist
            logs_dir = os.path.join(project_root, 'logs')
            os.makedirs(logs_dir, exist_ok=True, mode=0o755)
            
            # Create reasons subdirectory
            reasons_dir = os.path.join(logs_dir, 'reasons')
            os.makedirs(reasons_dir, exist_ok=True, mode=0o755)
            
            # Get current timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            
            # Create filename
            filename = f"monitoring_reason_{timestamp}.txt"
            filepath = os.path.join(reasons_dir, filename)
            
            # Collect process details
            process_details = []
            for pid in self.selected_processes:
                try:
                    proc = psutil.Process(pid)
                    process_details.append({
                        'pid': pid,
                        'name': proc.name(),
                        'username': proc.username()
                    })
                except psutil.NoSuchProcess:
                    continue
            
            # Write reason to file with proper permissions
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Monitoring started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Reason: {reason}\n\n")
                f.write("Processes being monitored:\n")
                for proc in process_details:
                    f.write(f"- PID: {proc['pid']}, Name: {proc['name']}, User: {proc['username']}\n")
                f.write("\n--- End of Monitoring Reason ---")
            
            # Set proper permissions for the file
            os.chmod(filepath, 0o644)
            
            return filepath
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save monitoring reason: {str(e)}")
            return None
