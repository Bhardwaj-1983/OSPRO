import os
import win32process
import win32api
import win32con
import win32security
from datetime import datetime
from typing import List, Dict, Optional
from .process_info import ProcessInfo

class ProcessMonitor:
    def __init__(self, sandbox_dir: str):
        self.sandbox_dir = sandbox_dir
        self.processes: Dict[int, ProcessInfo] = {}
        self.job_objects: Dict[str, int] = {}

    def add_process(self, pid: int, name: str, job_handle: int, sandbox_id: str):
        """Add a new process to monitoring."""
        try:
            # Get process start time
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            creation_time = win32process.GetProcessTimes(handle)[0]
            start_time = datetime.fromtimestamp(creation_time)
            win32api.CloseHandle(handle)

            # Create process info
            process_info = ProcessInfo(
                pid=pid,
                name=name,
                status="Running",
                start_time=start_time,
                sandbox_id=sandbox_id,
                job_handle=job_handle
            )

            # Store process info
            self.processes[pid] = process_info
            self.job_objects[sandbox_id] = job_handle

        except Exception as e:
            print(f"Failed to add process {pid}: {str(e)}")

    def get_processes(self) -> List[ProcessInfo]:
        """Get all monitored processes."""
        # Update process statuses
        for pid, process in list(self.processes.items()):
            try:
                handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
                if handle:
                    win32api.CloseHandle(handle)
                else:
                    process.status = "Terminated"
            except Exception:
                process.status = "Terminated"

        return list(self.processes.values())

    def kill_process(self, pid: int) -> bool:
        """Kill a specific process and its job object."""
        try:
            if pid in self.processes:
                process = self.processes[pid]
                
                # Kill the process
                handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
                if handle:
                    win32api.TerminateProcess(handle, 1)
                    win32api.CloseHandle(handle)

                # Terminate the job object
                if process.job_handle:
                    win32security.TerminateJobObject(process.job_handle, 1)

                # Remove from tracking
                del self.processes[pid]
                if process.sandbox_id in self.job_objects:
                    del self.job_objects[process.sandbox_id]

                return True
            return False
        except Exception as e:
            print(f"Failed to kill process {pid}: {str(e)}")
            return False

    def kill_all_processes(self) -> bool:
        """Kill all monitored processes."""
        success = True
        for pid in list(self.processes.keys()):
            if not self.kill_process(pid):
                success = False
        return success

    def cleanup(self):
        """Clean up all processes and job objects."""
        self.kill_all_processes()
        self.processes.clear()
        self.job_objects.clear() 