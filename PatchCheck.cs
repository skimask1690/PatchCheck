using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20; // Added for executable read permission
    private const uint MEM_COMMIT = 0x1000;

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("\nUsage: PatchCheck.exe <PID>");
            return;
        }

        int targetProcessId;
        if (!int.TryParse(args[0], out targetProcessId))
        {
            Console.WriteLine("\nInvalid process ID.");
            return;
        }

        // Validate if the process is running
        if (!IsProcessRunning(targetProcessId))
        {
            Console.WriteLine("\nProcess with ID " + targetProcessId + " is not running.");
            return;
        }

        IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, targetProcessId);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("\nFailed to open process. Error: " + Marshal.GetLastWin32Error());
            return;
        }

        Console.WriteLine("");
        Console.WriteLine("***********************************************");
        Console.WriteLine("                      AMSI                     ");
        Console.WriteLine("***********************************************");

        // Load amsi.dll
        IntPtr hAmsi = LoadLibrary("amsi.dll");
        if (hAmsi != IntPtr.Zero)
        {
            // Check for AMSI functions
            CheckFunction(hAmsi, hProcess, "AmsiScanBuffer");
            CheckFunction(hAmsi, hProcess, "AmsiOpenSession");
            CheckFunction(hAmsi, hProcess, "AmsiInitialize");
            CloseHandle(hAmsi);
        }
        else
        {
            Console.WriteLine("\nFailed to load amsi.dll. Error: " + Marshal.GetLastWin32Error());
        }

        Console.WriteLine("");
        Console.WriteLine("***********************************************");
        Console.WriteLine("                      ETW                      ");
        Console.WriteLine("***********************************************");

        // Load ntdll.dll
        IntPtr hNtdll = LoadLibrary("ntdll.dll");
        if (hNtdll != IntPtr.Zero)
        {
            // Check for ETW functions
            CheckFunction(hNtdll, hProcess, "EtwEventWrite");
            CheckFunction(hNtdll, hProcess, "NtTraceEvent");
            CloseHandle(hNtdll);
        }
        else
        {
            Console.WriteLine("\nFailed to load ntdll.dll. Error: " + Marshal.GetLastWin32Error());
        }

        CloseHandle(hProcess);
    }

    // Function to check if a process with the specified PID is running
    private static bool IsProcessRunning(int pid)
    {
        try
        {
            Process.GetProcessById(pid);
            return true; // Process is running
        }
        catch (ArgumentException)
        {
            return false; // Process is not running
        }
    }

    private static void CheckFunction(IntPtr hModule, IntPtr hProcess, string functionName)
    {
        IntPtr functionAddress = GetProcAddress(hModule, functionName);
        if (functionAddress == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get address of " + functionName + ". Error: " + Marshal.GetLastWin32Error());
            return;
        }

        // Check if the address is valid in the context of the target process
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, functionAddress, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == IntPtr.Zero ||
            mbi.State != MEM_COMMIT)
        {
            Console.WriteLine("\nInvalid address for " + functionName + ". MEMORY_BASIC_INFORMATION: BaseAddress=0x" + mbi.BaseAddress.ToString("X") + ", State=" + mbi.State + ", Protect=" + mbi.Protect);
            return;
        }

        // Check if the memory is readable
        if (mbi.Protect != PAGE_READWRITE && mbi.Protect != PAGE_EXECUTE_READ)
        {
            Console.WriteLine("\n" + functionName + " is not in a readable state. Protect=" + mbi.Protect);
            return;
        }

        // Read the bytes at the function address
        const int bufferSize = 64; // Adjust size as needed
        byte[] buffer = new byte[bufferSize];
        int bytesRead;

        bool readSuccess = ReadProcessMemory(hProcess, functionAddress, buffer, (uint)buffer.Length, out bytesRead);
        if (!readSuccess)
        {
            Console.WriteLine("Failed to read memory for " + functionName + ". Error: " + Marshal.GetLastWin32Error());
            return;
        }

        if (bytesRead < buffer.Length)
        {
            Console.WriteLine("\nIncorrect bytes read: " + bytesRead);
        }

        Console.WriteLine("\nBytes read from " + functionName + ":");
        for (int i = 0; i < bytesRead; i++)
        {
            Console.Write(buffer[i].ToString("X2") + " ");

            // Insert a new line every 16 bytes for clarity
            if ((i + 1) % 16 == 0)
            {
                Console.WriteLine(); // Print a new line
            }
        }
    }
}
