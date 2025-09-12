#!/usr/bin/env python3
import sys

def test_tkinter():
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title("Test GUI")
        label = tk.Label(root, text="GUI Test Successful!")
        label.pack(pady=20)
        
        def close_app():
            root.destroy()
            
        button = tk.Button(root, text="Close", command=close_app)
        button.pack(pady=10)
        
        # Auto close after 3 seconds for testing
        root.after(3000, close_app)
        root.mainloop()
        return True
    except Exception as e:
        print(f"Tkinter test failed: {e}")
        return False

def test_pyqt():
    try:
        from PyQt6.QtWidgets import QApplication, QLabel, QWidget
        from PyQt6.QtCore import QTimer
        
        app = QApplication(sys.argv)
        window = QWidget()
        window.setWindowTitle("PyQt6 Test")
        window.setGeometry(100, 100, 300, 200)
        
        label = QLabel("PyQt6 Test Successful!", window)
        label.move(50, 50)
        
        window.show()
        
        # Auto close after 3 seconds
        timer = QTimer()
        timer.timeout.connect(app.quit)
        timer.start(3000)
        
        app.exec()
        return True
    except Exception as e:
        print(f"PyQt6 test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing GUI frameworks...")
    
    print("1. Testing Tkinter...")
    if test_tkinter():
        print("✓ Tkinter works!")
    else:
        print("✗ Tkinter failed!")
    
    print("\n2. Testing PyQt6...")
    if test_pyqt():
        print("✓ PyQt6 works!")
    else:
        print("✗ PyQt6 failed!")