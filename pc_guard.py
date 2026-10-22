"""PC Guard - virus scanning (Microsoft Defender plus its own engine) and storage cleaning for Windows.

Run without arguments for the app; `--task scan` / `--task clean` / `--task monitor` is what Task Scheduler runs.
"""
import sys

from core import TASK_NAMES, run_task

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--task" and (sys.argv[2] in TASK_NAMES or sys.argv[2] == "monitor"):
        run_task(sys.argv[2])
        sys.exit(0)
    from ui import main
    main()
