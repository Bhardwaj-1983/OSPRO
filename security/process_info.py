from datetime import datetime
from dataclasses import dataclass

@dataclass
class ProcessInfo:
    pid: int
    name: str
    status: str
    start_time: datetime
    sandbox_id: str
    job_handle: int = None 