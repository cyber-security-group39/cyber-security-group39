import logging
import traceback
from datetime import datetime
import json
import os
from functools import wraps
from typing import Callable, Any, Dict

class SupremeErrorHandler:
   
    
    def __init__(self):
        self.error_count = 0
        self.max_errors = 50
        self.critical_errors = 0
        self.max_critical_errors = 5
        self.error_log = []
        
    def protect_process(self, func: Callable) -> Callable:
    
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                self.handle_error(e, func.__name__)
                return None
        return wrapper
    
    def handle_error(self, error: Exception, context: str = "Unknown") -> None:
        
        self.error_count += 1
        error_info = {
            'timestamp': datetime.now().isoformat(),
            'context': context,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc()
        }
        
        self.error_log.append(error_info)
        
      
        logging.error(f"Error in {context}: {error}")
        logging.error(traceback.format_exc())
        
       
        if self.error_count > self.max_errors:
            logging.critical("Maximum error threshold exceeded. Application may become unstable.")
        
      
        if isinstance(error, (MemoryError, SystemError, RuntimeError)):
            self.critical_errors += 1
            if self.critical_errors >= self.max_critical_errors:
                self.emergency_shutdown("Too many critical errors detected")
    
    def emergency_shutdown(self, reason: str) -> None:
      
        logging.critical(f"EMERGENCY SHUTDOWN: {reason}")
        print(f"CRITICAL: {reason}. Application shutting down.")
        
     
        try:
            with open('emergency_recovery.json', 'w') as f:
                json.dump({
                    'shutdown_time': datetime.now().isoformat(),
                    'reason': reason,
                    'recent_errors': self.error_log[-10:] if self.error_log else []
                }, f, indent=2)
        except:
            pass
            
        os._exit(1)
    
    def get_error_summary(self) -> Dict[str, Any]:
        
        return {
            'total_errors': self.error_count,
            'critical_errors': self.critical_errors,
            'recent_errors': self.error_log[-5:] if self.error_log else []
        }
    
    def reset_error_count(self) -> None:
       
        self.error_count = 0
        self.critical_errors = 0


error_handler = SupremeErrorHandler()
