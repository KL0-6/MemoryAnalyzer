using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WebSocketSharp.Server;
using WebSocketSharp;
using System.Net.Sockets;
using static System.Net.Mime.MediaTypeNames;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace UwpDumperConsole
{
    internal class Program
    {
        public static WebSocketServer socket = null;

        public class ipc_class : WebSocketBehavior
        {
            protected override void OnMessage(MessageEventArgs e)
            {
                Console.Write(e.Data.ToString());
            }

            protected override void OnClose(CloseEventArgs e)
            {
                Environment.Exit(0);
            }
        }

        static IntPtr phandle;
        static int pid = 0;

        public enum Result : uint
        {
            Success,
            DLLNotFound,
            OpenProcFail,
            AllocFail,
            LoadLibFail,
            AlreadyInjected,
            ProcNotOpen,
            Unknown,
        }

        static readonly IntPtr NULL = (IntPtr)0;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inhert_handle, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static Result r_inject(string dll_path)
        {
            FileInfo finfo = new FileInfo(dll_path);
            FileSecurity fs = finfo.GetAccessControl();
            SecurityIdentifier se = new SecurityIdentifier("S-1-15-2-1");
            fs.AddAccessRule(new FileSystemAccessRule(se, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
            finfo.SetAccessControl(fs);

            var proc_list = Process.GetProcessesByName("Windows10Universal");

            if (proc_list.Length == 0)
                return Result.ProcNotOpen;

            for (uint i = 0; i < proc_list.Length; i++)
            {
                var proc = proc_list[i];
                if (pid != proc.Id)
                {
                    var _phandle = OpenProcess(0x0002 | 0x0400 | 0x0008 | 0x0020 | 0x0010, false, proc.Id);
                    if (_phandle == NULL)
                        return Result.OpenProcFail;

                    var alloc = VirtualAllocEx(_phandle, NULL, (IntPtr)((dll_path.Length + 1) * Marshal.SizeOf(typeof(char))), 0x00002000 | 0x00001000, 0x40);

                    if (alloc == NULL)
                        return Result.AllocFail;

                    var bytes = Encoding.Default.GetBytes(dll_path);
                    var permissions = WriteProcessMemory(_phandle, alloc, bytes, (IntPtr)((dll_path.Length + 1) * Marshal.SizeOf(typeof(char))), 0);
                    if (permissions == 0 || permissions == 6L)
                        return Result.Unknown;

                    if (CreateRemoteThread(_phandle, NULL, NULL, GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), alloc, 0, NULL) == NULL)
                        return Result.LoadLibFail;

                    pid = proc.Id;
                    phandle = _phandle;

                    return Result.Success;
                }
                else if (pid == proc.Id)
                    return Result.AlreadyInjected;
            }

            return Result.Unknown;
        }

        static void Main(string[] args)
        {
            Console.Title = "UwpDumper!";


            socket = new WebSocketServer(64609, false);
            socket.AddWebSocketService<ipc_class>("/dumper_ipc");
            socket.Start();


            if (!File.Exists(Environment.CurrentDirectory + "\\UwpDumper.dll"))
            {
                Console.WriteLine("Failure to find UwpDumper.dll!");
            }

            r_inject(Environment.CurrentDirectory + "\\UwpDumper.dll");

            while (socket.IsListening)
            {

            }
        }
    }
}
