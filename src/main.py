import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
import platform
import logging
import signal

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the src directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.frontend.main_window import SystemCallInterface

def signal_handler(signum, frame):
    """Handle system signals gracefully"""
    logger.info(f"Received signal {signum}")
    QApplication.quit()

def check_root():
    """Check if the application is running with root privileges"""
    logger.debug(f"Checking root privileges. EUID: {os.geteuid()}")
    if os.geteuid() != 0:
        logger.error("Application must be run with root privileges")
        print("Error: This application requires root privileges.")
        print("Please run with sudo.")
        sys.exit(1)
    logger.debug("Root privileges confirmed")

def main():
    try:
        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Check for root privileges first
        check_root()
        
        logger.debug("Initializing QApplication")
        app = QApplication(sys.argv)
        
        # Ensure clean shutdown
        app.aboutToQuit.connect(app.deleteLater)
        
        logger.debug("Creating main window")
        window = SystemCallInterface()
        
        logger.debug("Showing main window")
        window.show()
        
        logger.debug("Entering Qt event loop")
        sys.exit(app.exec())
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
