import ctypes
import sys
import os
import psutil

# Define necessary constants
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)

# Load the required Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def get_process_handle(pid):
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Failed to open process {pid}: {ctypes.get_last_error()}")
    return h_process

def allocate_memory(h_process, size):
    arg_address = kernel32.VirtualAllocEx(h_process, 0, size, VIRTUAL_MEM, 0x04)
    if not arg_address:
        print(f"Failed to allocate memory in the target process: {ctypes.get_last_error()}")
    return arg_address

def write_memory(h_process, address, data):
    written = ctypes.c_int(0)
    if not kernel32.WriteProcessMemory(h_process, address, data, len(data), ctypes.byref(written)):
        print(f"Failed to write to process memory: {ctypes.get_last_error()}")
        return False
    return True

def create_remote_thread(h_process, func_address, arg_address):
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, func_address, arg_address, 0, None)
    if not h_thread:
        print(f"Failed to create remote thread: {ctypes.get_last_error()}")
    return h_thread

def inject_dll(pid, dll_path):
    h_process = get_process_handle(pid)
    if not h_process:
        return False

    dll_path_bytes = dll_path.encode('utf-8')
    dll_path_size = len(dll_path_bytes) + 1
    arg_address = allocate_memory(h_process, dll_path_size)
    if not arg_address:
        kernel32.CloseHandle(h_process)
        return False

    if not write_memory(h_process, arg_address, dll_path_bytes):
        kernel32.VirtualFreeEx(h_process, arg_address, dll_path_size, 0x8000)
        kernel32.CloseHandle(h_process)
        return False

    h_kernel32 = kernel32.GetModuleHandleA(b'kernel32.dll')
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')
    if not h_loadlib:
        print(f"Failed to get address of LoadLibraryA: {ctypes.get_last_error()}")
        kernel32.VirtualFreeEx(h_process, arg_address, dll_path_size, 0x8000)
        kernel32.CloseHandle(h_process)
        return False

    h_thread = create_remote_thread(h_process, h_loadlib, arg_address)
    if not h_thread:
        kernel32.VirtualFreeEx(h_process, arg_address, dll_path_size, 0x8000)
        kernel32.CloseHandle(h_process)
        return False

    kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)

    kernel32.VirtualFreeEx(h_process, arg_address, dll_path_size, 0x8000)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)

    print("DLL injected successfully.")
    return True

def find_pid_by_name(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <process_name> <dll_path>")
        sys.exit(1)

    process_name = sys.argv[1]
    dll_path = sys.argv[2]

    if not os.path.isfile(dll_path):
        print(f"Error: DLL not found at {dll_path}")
        sys.exit(1)

    pid = find_pid_by_name(process_name)
    if not pid:
        print(f"Error: Process '{process_name}' not found.")
        sys.exit(1)

    if inject_dll(pid, dll_path):
        print("Injection completed successfully.")
    else:
        print("Injection failed.")
