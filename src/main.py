import sys
import os
from PyQt6.QtWidgets import QApplication

# Add the src directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.frontend.main_window import SystemCallInterface

def main():
    app = QApplication(sys.argv)
    window = SystemCallInterface()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
