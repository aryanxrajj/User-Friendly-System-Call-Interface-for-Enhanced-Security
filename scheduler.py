import tkinter as tk
from tkinter import ttk, messagebox
import heapq
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class Task:
    def __init__(self, pid, burst, priority):
        self.pid, self.burst, self.priority = pid, burst, priority
    def __lt__(self, other):
        return (self.burst < other.burst) or (self.burst == other.burst and self.priority > other.priority)

class SchedulerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("⚡ Energy-Efficient CPU Scheduler")
        self.setup_ui()
        self.tasks = []
        self.theme = "dark"
        
    def setup_ui(self):
        self.root.configure(bg="#7B2CBF")
        
        # Header
        self.header = tk.Frame(self.root, bg="#7B2CBF")
        self.header.pack(pady=20)
        tk.Label(self.header, text="⚡ Energy-Efficient CPU Scheduler", font=("Arial", 18), 
                bg="#2E3440", fg="#ECEFF4").pack()
        
        # Input Section
        input_frame = tk.Frame(self.root, bg="#3B4252", padx=20, pady=10)
        input_frame.pack(pady=10)
        
        tk.Label(input_frame, text="Task ID:", bg="#3B4252", fg="#ECEFF4").grid(row=0, column=0, sticky="e")
        self.pid_entry = tk.Entry(input_frame, width=10)
        self.pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="Burst Time:", bg="#3B4252", fg="#ECEFF4").grid(row=1, column=0, sticky="e")
        self.burst_entry = tk.Entry(input_frame, width=10)
        self.burst_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="Priority (1-5):", bg="#3B4252", fg="#ECEFF4").grid(row=2, column=0, sticky="e")
        self.priority_entry = tk.Entry(input_frame, width=10)
        self.priority_entry.grid(row=2, column=1, padx=5, pady=5)
        
        button_frame = tk.Frame(self.root, bg="#2E3440")
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="➕ Add Task", command=self.add_task, bg="#5E81AC", fg="white").pack(side="left", padx=5)
        tk.Button(button_frame, text="⏳ Schedule Tasks", command=self.schedule, bg="#A3BE8C", fg="white").pack(side="left", padx=5)
        tk.Button(button_frame, text="🎨 Toggle Theme", command=self.toggle_theme, bg="#D08770", fg="white").pack(side="left", padx=5)
        tk.Button(button_frame, text="❌ Exit", command=self.root.quit, bg="#BF616A", fg="white").pack(side="left", padx=5)
        
        # Task Table
        self.table = ttk.Treeview(self.root, columns=("PID", "Burst", "Priority"), show="headings")
        self.table.heading("PID", text="Task ID")
        self.table.heading("Burst", text="Burst Time")
        self.table.heading("Priority", text="Priority")
        self.table.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Gantt Chart
        self.figure = Figure(figsize=(10, 3), dpi=100)
        self.plot = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.root)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
        
    def add_task(self):
        try:
            pid = int(self.pid_entry.get())
            burst = int(self.burst_entry.get())
            priority = int(self.priority_entry.get())
            if priority < 1 or priority > 5:
                raise ValueError
            self.tasks.append(Task(pid, burst, priority))
            self.table.insert("", "end", values=(pid, burst, priority))
            self.pid_entry.delete(0, tk.END)
            self.burst_entry.delete(0, tk.END)
            self.priority_entry.delete(0, tk.END)
        except:
            tk.messagebox.showerror("Error", "Invalid input!")
            
    def schedule(self):
        if not self.tasks:
            tk.messagebox.showwarning("Warning", "No tasks to schedule!")
            return
            
        heapq.heapify(self.tasks)
        scheduled = []
        energy = 0
        time = 0
        gantt_data = []
        
        while self.tasks:
            task = heapq.heappop(self.tasks)
            scheduled.append(task)
            task_energy = task.burst * (1 / task.priority)
            energy += task_energy
            gantt_data.append((task.pid, time, time + task.burst))
            time += task.burst
        
        # Update Gantt Chart
        self.plot.clear()
        for i, (pid, start, end) in enumerate(gantt_data):
            self.plot.broken_barh([(start, end - start)], (i - 0.4, 0.8), facecolors='tab:blue')
            self.plot.text((start + end) / 2, i, f"P{pid}", ha='center', va='center', color='white')
        self.plot.set_title("Gantt Chart (Task Execution Timeline)")
        self.plot.set_xlabel("Time")
        self.plot.set_yticks([])
        self.canvas.draw()
        
        tk.messagebox.showinfo("Scheduling Complete", f"Total Energy: {energy:.2f}\nEfficiency: {(1 - (energy / sum(t.burst for t in scheduled))) * 100:.1f}%")
    
    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        bg = "#ECEFF4" if self.theme == "light" else "#2E3440"
        fg = "#2E3440" if self.theme == "light" else "#ECEFF4"
        self.root.configure(bg=bg)
        self.header.configure(bg=bg)
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=bg)
            if hasattr(widget, 'config'):
                widget.config(bg=bg, fg=fg)

if __name__ == "__main__":
    root = tk.Tk()
    app = SchedulerApp(root)
    root.mainloop()
