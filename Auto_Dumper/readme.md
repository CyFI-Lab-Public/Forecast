#### 

# Documentation for Auto_Dumper

Welcome to the Documentation for Auto_Dumper! This is a tool for creating Windows memory dumps at specific memory addresses. This was created by students at the Georgia Institute of Technology to work with the Forecast memory forensics tool that was developed at the GT CyFI lab: https://github.com/CyFI-Lab-Public/Forecast

## 1. Sturcture

+ class ProcessManager:
  - Manage process, search process PID and kill process
  - Currently unused
+ class GDBManager:
  - Manage GDB, to insert and remove breakpoints

## 2. Using Auto_Dumper

### Dependencies:
Auto_Dumper works on Windows with gdb installed. In order to install gdb, users can install msys2 from here: [msys2](https://www.msys2.org/). Users can then install `gdb` on msys2 by running the following command: `pacman -S gdb`.

Please also install the following python package(s) in your msys2 environment:
`pip install pygdbmi`

This script relies on [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to take a memory dump of running processes. You can find the executables in the `./procdump` folder. You can also download yourself if you wish. Please make sure the `write_dump()` function is invoking the version of procdump that matches your operating system.

### Usage:
`python auto_dumper.py [breakpoint instruction address] [malware exe name]`

For example: `python auto_dumper.py 0x123456 webc2-greencat-2.exe`

After the script terminates, you should find a `.dmp` file in the root directory of the project. If the script reports `Exited with code: 1`, it's expected behavior and your dump file's integrity is not affected.
