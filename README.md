# 🛠️ PatchCheck

**PatchCheck** is a C# tool that scans a running process for potential patches to functions in **AMSI (Antimalware Scan Interface)** and **ETW (Event Tracing for Windows)**. It reads process memory and extracts function bytes to detect tampering.

## 🔍 Features
- Reads memory of a target process using **ReadProcessMemory**.
- Checks for the presence of **AmsiScanBuffer, AmsiOpenSession, AmsiInitialize** in `amsi.dll`.
- Checks for **EtwEventWrite, NtTraceEvent** in `ntdll.dll`.
- Uses **VirtualQueryEx** to validate memory protection and state.
- Displays function bytes to help identify patches or hooks.

## 🚀 Usage

- Run the executable with the target process ID as an argument:

   ```sh
   PatchCheck.exe <PID>
   ```

   - `<PID>`: Process ID of the target process to scan.

## 📜 Notes
- This tool is useful for detecting AMSI/ETW bypass techniques used by malware.
- It does not modify process memory—only reads it for analysis.
- Ensure you have the necessary permissions before scanning system processes.

---

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

---

## 📜 License

This project is released under the [MIT License](LICENSE).
