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

            // CLI mode: Phantom.exe --cli <input.exe> <output.bat>
            if (args.Length >= 2 && args[0] == "--cli")
            {
                AllocConsole();
                string inputPath = args[1];
                string outputPath = args.Length >= 3 ? args[2] : Path.ChangeExtension(inputPath, ".bat");

                try
                {
                    CliBuilder.Build(inputPath, outputPath);
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
