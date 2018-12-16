import os
import sys
from cx_Freeze import setup, Executable
from pathlib import Path

build_dir = Path(__file__).parent / "build" / "-".join(
    ["signal_bkp_decrypt", sys.platform]
)

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {
    "packages": ["google", "cffi", "cryptography", "requests", "fs",
                 "filetype"],
    "excludes": ["tkinter", "PyQt4", "PyQt5", "matplotlib", "scipy"],
    "optimize": 2,
    "build_exe": str(build_dir)
    }

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
if sys.platform == "win32":
    base = "Win32GUI"
    target_name = "signal_bkp_decrypt.exe"
else:
    target_name = "run"

setup(
    name="signal-bkp-decrypt",
    version="0.1.0",
    description="Decrypts a Signal backup.",
    options={"build_exe": build_exe_options},
    executables=[
        Executable(
            "signal_backup_manager/cli.py",
            base=base,
            targetName="signal_bkp_decrypt.exe"
        )
    ]
)

if sys.platform != "win32":
    launch_script = build_dir / "signal_bkp_decrypt.sh"
    launch_script.write_text("""#!/bin/bash\nLD_LIBRARY_PATH=./lib ./run\n""")
    os.chmod(str(launch_script), 0o775)
