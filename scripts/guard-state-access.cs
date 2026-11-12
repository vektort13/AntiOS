using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AntiOS {
    // Used by the installed Windows PowerShell 5.1 helper. ACLs are read and
    // written on the same open object. File contents are never opened for I/O.
    public static class GuardFileAccess {
        [StructLayout(LayoutKind.Sequential)]
        struct FileStandardInfo {
            public long AllocationSize, FileSize;
            public uint Links;
            public byte DeletePending, Directory;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct UnicodeString {
            public ushort Length, MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct ObjectAttributes {
            public int Length;
            public IntPtr Root, Name;
            public uint Attributes;
            public IntPtr Security, QualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct IoStatus { public IntPtr Status, Information; }

        [DllImport("ntdll.dll")]
        static extern int NtOpenFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
            out IoStatus status, FileShare share, uint options);
        [DllImport("ntdll.dll")]
        static extern uint RtlNtStatusToDosError(int status);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out FileStandardInfo info, uint size);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);
        [DllImport("advapi32.dll", SetLastError=true)]
        static extern bool GetKernelObjectSecurity(SafeFileHandle file, uint sections, byte[] data,
            uint length, out uint needed);
        [DllImport("advapi32.dll", SetLastError=true)]
        static extern bool SetKernelObjectSecurity(SafeFileHandle file, uint sections, byte[] data);

        static SafeFileHandle Open(string path, bool directory) {
            // CreateFile adds access requirements that fail on an owner-only
            // DACL. Open only READ_CONTROL and WRITE_DAC and refuse reparsing
            // any component, including the final one.
            string fullPath = Path.GetFullPath(path);
            if (fullPath.Length < 3 || fullPath[1] != ':') throw new IOException("Expected a local Guard path.");
            string ntPath = @"\??\" + fullPath;
            var text = new UnicodeString { Buffer = ntPath, Length = checked((ushort)(2 * ntPath.Length)),
                MaximumLength = checked((ushort)(2 * ntPath.Length + 2)) };
            var attributes = new ObjectAttributes { Length = Marshal.SizeOf(typeof(ObjectAttributes)),
                Attributes = 0x40 | 0x1000, Name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString))) };
            SafeFileHandle handle;
            int status;
            try {
                Marshal.StructureToPtr(text, attributes.Name, false);
                IoStatus io;
                status = NtOpenFile(out handle, (uint)(FileSystemRights.ReadPermissions | FileSystemRights.ChangePermissions),
                    ref attributes, out io, FileShare.ReadWrite, directory ? 1u : 0x40u);
            } finally {
                Marshal.DestroyStructure(attributes.Name, typeof(UnicodeString));
                Marshal.FreeHGlobal(attributes.Name);
            }
            if (status < 0) {
                int error = (int)RtlNtStatusToDosError(status);
                if (handle != null) handle.Dispose();
                if (!directory && error == 2) return null;
                throw new Win32Exception(error, "Cannot open " + Path.GetFileName(path) + " for ACL repair (Win32 " + error + ").");
            }
            try {
                FileStandardInfo info;
                if (!GetFileInformationByHandleEx(handle, 1, out info, (uint)Marshal.SizeOf(typeof(FileStandardInfo))))
                    throw new Win32Exception();
                if (info.DeletePending != 0 || (!directory && info.Links != 1))
                    throw new IOException("Guard state is linked or being removed.");
                var name = new StringBuilder(32768);
                uint size = GetFinalPathNameByHandle(handle, name, (uint)name.Capacity, 0);
                if (size == 0) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot verify the final Guard path.");
                if (size >= name.Capacity || !String.Equals(name.ToString(), @"\\?\" + Path.GetFullPath(path),
                        StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Guard state path is redirected.");
                return handle;
            } catch { handle.Dispose(); throw; }
        }

        static void Grant(SafeFileHandle handle, SecurityIdentifier user, bool directory) {
            const uint dacl = 4;
            uint size;
            if (!GetKernelObjectSecurity(handle, dacl, null, 0, out size) && Marshal.GetLastWin32Error() != 122)
                throw new Win32Exception();
            byte[] bytes = new byte[size];
            if (!GetKernelObjectSecurity(handle, dacl, bytes, size, out size)) throw new Win32Exception();
            FileSystemSecurity acl = directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            acl.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
            // Do not short-circuit on the ACL returned by the native handle:
            // its inherited ACE flags can be normalized differently from Get-Acl.
            // An inherited grant is NOT proof of an explicit grant on this file.
            // Set only the current user's explicit allow rule, preserving other SIDs.
            acl.SetAccessRule(new FileSystemAccessRule(
                user, FileSystemRights.FullControl, InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
            // Set only this handle's DACL, without propagating into unrelated children.
            if (!SetKernelObjectSecurity(handle, dacl, acl.GetSecurityDescriptorBinaryForm())) throw new Win32Exception();
        }

        public static void Repair(string directory, SecurityIdentifier user) {
            string[] files = { "guard.sqlite3", "guard.sqlite3-wal", "guard.sqlite3-shm", "guard.sqlite3-journal",
                "guard.lock", "startup-policy.json", "startup-error.json" };
            using (var root = Open(directory, true)) {
                var opened = new List<SafeFileHandle>();
                try {
                    foreach (string file in files) {
                        var handle = Open(Path.Combine(directory, file), false);
                        if (handle != null) opened.Add(handle);
                    }
                    foreach (var handle in opened) Grant(handle, user, false);
                    Grant(root, user, true);
                } finally { foreach (var handle in opened) handle.Dispose(); }
            }
        }
    }
}
