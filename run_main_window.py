#!/usr/bin/env python3
"""
Direct launcher for the System Call Interface main window
"""
import sys
import os

# Add the src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from PyQt6.QtWidgets import QApplication
    from frontend.main_window import SystemCallInterface
    
    def main():
        print("🚀 Starting System Call Interface...")
        print("Note: This application requires root privileges for full functionality")
        
        app = QApplication(sys.argv)
        
        try:
            window = SystemCallInterface()
            window.show()
            
            print("✅ Application window created successfully")
            print("🔐 Please use login credentials: admin/admin123")
            
            sys.exit(app.exec())
            
        except Exception as e:
            print(f"❌ Error creating main window: {e}")
            print("This might be due to:")
            print("  1. Missing root privileges (try: sudo python3 run_main_window.py)")
            print("  2. Display/GUI environment issues")
            print("  3. Missing dependencies")
            return 1
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all dependencies are installed:")
    print("  pip3 install -r requirements.txt")
    sys.exit(1)