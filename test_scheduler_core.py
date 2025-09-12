#!/usr/bin/env python3
"""
Test the core scheduling algorithm without GUI
"""
import heapq

class Task:
    def __init__(self, pid, burst, priority):
        self.pid, self.burst, self.priority = pid, burst, priority
    
    def __lt__(self, other):
        return (self.burst < other.burst) or (self.burst == other.burst and self.priority > other.priority)
    
    def __repr__(self):
        return f"Task(pid={self.pid}, burst={self.burst}, priority={self.priority})"

def schedule_tasks(tasks):
    """Schedule tasks using SJF with priority"""
    heapq.heapify(tasks)
    scheduled = []
    energy = 0
    time = 0
    gantt_data = []
    
    print("Scheduling Tasks...")
    print("-" * 50)
    
    while tasks:
        task = heapq.heappop(tasks)
        scheduled.append(task)
        task_energy = task.burst * (1 / task.priority)
        energy += task_energy
        gantt_data.append((task.pid, time, time + task.burst))
        
        print(f"Time {time:2d}-{time + task.burst:2d}: Process P{task.pid} (Burst: {task.burst}, Priority: {task.priority})")
        time += task.burst
    
    print("-" * 50)
    print(f"Total Energy: {energy:.2f}")
    total_burst = sum(t.burst for t in scheduled)
    efficiency = (1 - (energy / total_burst)) * 100 if total_burst > 0 else 0
    print(f"Efficiency: {efficiency:.1f}%")
    print(f"Total Time: {time}")
    
    return scheduled, energy, efficiency, gantt_data

def main():
    print("🚀 Energy-Efficient CPU Scheduler (Core Test)")
    print("=" * 60)
    
    # Sample tasks
    tasks = [
        Task(1, 6, 3),
        Task(2, 8, 1),
        Task(3, 7, 2),
        Task(4, 3, 4),
        Task(5, 4, 5)
    ]
    
    print("Initial Tasks:")
    for task in tasks:
        print(f"  {task}")
    
    print("\n" + "=" * 60)
    
    # Schedule the tasks
    scheduled, energy, efficiency, gantt = schedule_tasks(tasks.copy())
    
    print("\nGantt Chart:")
    print("-" * 50)
    for pid, start, end in gantt:
        print(f"P{pid}: {'█' * (end - start)} ({start}-{end})")
    
    print(f"\n✅ Scheduling Complete!")
    print(f"📊 Performance Metrics:")
    print(f"   • Total Energy Consumption: {energy:.2f}")
    print(f"   • System Efficiency: {efficiency:.1f}%")
    print(f"   • Total Execution Time: {gantt[-1][2] if gantt else 0}")

if __name__ == "__main__":
    main()