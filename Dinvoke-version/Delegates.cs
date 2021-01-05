using System;
using System.Runtime.InteropServices;
using System.Text;
using DInvoke.Data;

namespace SharpHandler
{
    public class Delegates
    {

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS RtlAdjustPrivilege(int privilege, bool bEnablePrivilege, bool isThreadPrivilege, out bool previousValue);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool QueryFullProcessImageName(IntPtr hprocess, int dwFlags, StringBuilder lpExeName, out int size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtQuerySystemInformation(Structs.SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, Structs.DuplicateOptions dwOptions);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Native.NTSTATUS NtQueryObject(IntPtr ObjectHandle, Structs.OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation, int ObjectInformationLength, ref int ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

    }
}
