import os
import subprocess
import time
import signal
import sys

class ProcessRunner:
    def __init__(self, process_name):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.process_name = os.path.join(self.script_dir, process_name)
        self.process = None
    
    def StartProcess(self, args=None):
        try:
            if not os.path.exists(self.process_name):
                raise FileNotFoundError(f"File {self.process_name} not found")
            
            # Prepare the command list
            cmd = [self.process_name]
            if args:
                if isinstance(args, (list, tuple)):
                    cmd.extend(args)
                else:
                    cmd.append(str(args))
                    
            self.process = subprocess.Popen(
                cmd,  # Use the command list instead of just the process name
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            print(f"[+] Process Started Successfully PID:{self.process.pid}")
            print(f"[+] Command: {' '.join(cmd)}")
            return True
        except Exception as e:
            print(f"[!] Error Starting Process: {e}")
            return False
    
    def StopProcess(self):
        try:
            if not self.process:
                print("[!] No process running")
                return
            
            if sys.platform == "win32":
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.process.send_signal(signal.SIGTERM)
            
            self.process.wait(timeout=5)
            print("[+] Process Stopped Successfully")
        except subprocess.TimeoutExpired:
            self.process.kill()
            print("[!] Process Forcefully Terminated")
        except Exception as e:
            print(f"[!] Error Stopping Process {e}")

if __name__ == "__main__":
    # Debugging info
    print("Current directory:", os.getcwd())
    print("Directory contents:", os.listdir())
    
    # proc = ProcessRunner("malpacket.exe")
    # if proc.StartProcess():
    #     time.sleep(5)
    #     proc.StopProcess()

    proc = ProcessRunner("packetsniffer.targeted.exe")
    if proc.StartProcess("192.168.0.130"):
        time.sleep(5)
        proc.StopProcess()