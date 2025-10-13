import psutil
import logging
import sys
print(sys.path)

class ProcessMonitor:
  
    
    def __init__(self):
        self.max_cpu_percent = 80 
        self.max_memory_percent = 75 
        self.thread_limits = {} 
    
    def check_system_resources(self) -> bool:
       
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        
        if cpu_percent > self.max_cpu_percent:
            logging.warning(f"High CPU usage detected: {cpu_percent}%")
            return False
            
        if memory_percent > self.max_memory_percent:
            logging.warning(f"High memory usage detected: {memory_percent}%")
            return False
            
        return True
    
    def adaptive_thread_management(self, operation: str, default_threads: int) -> int:
      
        if not self.check_system_resources():
           
            return max(1, default_threads // 2)

        if operation not in self.thread_limits:
            self.thread_limits[operation] = default_threads
        
        return self.thread_limits[operation]


process_monitor = ProcessMonitor()
