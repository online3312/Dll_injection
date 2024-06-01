# DLL Injector with PID Finder

This repository contains a Python script to perform DLL injection into a target process. The script includes functionality to find the PID (Process ID) of a process by its name and then inject a specified DLL into that process.

## Prerequisites

- Python 3.x
- `psutil` library
- Administrative privileges (on Windows)

## Installation

1. **Clone the repository**:

    ```sh
    git clone https://github.com/yourusername/dll-injector.git
    cd dll-injector
    ```

2. **Install the required library**:

    ```sh
    pip install psutil
    ```

## Usage

1. **Prepare the DLL to be injected**: Ensure you have a DLL ready and accessible.

2. **Run the script**:

    ```sh
    python injector_with_pid_finder.py <process_name> <path_to_dll>
    ```

    - `<process_name>`: The name of the process you want to inject the DLL into (e.g., `notepad.exe`).
    - `<path_to_dll>`: The full path to the DLL file you want to inject.

### Example

To inject a DLL located at `C:\path\to\your.dll` into a running Notepad process, run:

```sh
python injector_with_pid_finder.py notepad.exe C:\path\to\your.dll
