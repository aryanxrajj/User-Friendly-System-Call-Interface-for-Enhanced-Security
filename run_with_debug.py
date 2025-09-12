#!/usr/bin/env python3
"""
Debug launcher for the System Call Interface with detailed logging
"""
import sys
import os
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def main():
    print("🚀 System Call Interface - Debug Mode")
    print("=" * 50)
    
    try:
        print("📦 Importing PyQt6...")
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        print("✅ PyQt6 imported successfully")
        
        print("📦 Importing main window...")
        from frontend.main_window import SystemCallInterface
        print("✅ Main window imported successfully")
        
        print("🖥️  Creating QApplication...")
        app = QApplication(sys.argv)
        print("✅ QApplication created")
        
        print("🏗️  Creating main window...")
        try:
            window = SystemCallInterface()
            print("✅ Main window created successfully")
            
            print("👁️  Showing window...")
            window.show()
            print("✅ Window shown")
            
            print("🔐 Login credentials: admin/admin123")
            print("⚠️  Note: Application requires root privileges for full monitoring")
            print("🎯 Starting event loop...")
            
            # Start the application
            result = app.exec()
            print(f"📊 Application exited with code: {result}")
            return result
            
        except PermissionError as e:
            print(f"❌ Permission Error: {e}")
            print("💡 Try running with: sudo python3 run_with_debug.py")
            return 1
            
        except Exception as e:
            print(f"❌ Error creating window: {e}")
            print(f"📋 Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return 1
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("📋 Missing dependencies. Install with:")
        print("   pip3 install PyQt6 bcrypt PyJWT reportlab")
        return 1
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Application interrupted by user")
        sys.exit(0)