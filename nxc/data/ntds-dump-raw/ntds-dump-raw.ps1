Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class CNativeMethods
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName, 
        uint dwDesiredAccess, 
        uint dwShareMode, 
        IntPtr lpSecurityAttributes, 
        uint dwCreationDisposition, 
        uint dwFlagsAndAttributes, 
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        SafeFileHandle hFile, 
        byte[] lpBuffer, 
        uint nNumberOfBytesToRead, 
        out uint lpNumberOfBytesRead, 
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile, 
        long lDistanceToMove, 
        out long lpNewFilePointer, 
        uint dwMoveMethod
    );
}

public enum EMoveMethod : uint
{
    Begin = 0,
    Current = 1,
    End = 2
}
"@
Function read_disk{
    $offset = [long]$args[0]
    $size = [int]$args[1]
    try {
        $handle = [CNativeMethods]::CreateFile("\\.\PHYSICALDRIVE0", 
            [CNativeMethods]::GENERIC_READ, 
            [CNativeMethods]::FILE_SHARE_READ -bor [CNativeMethods]::FILE_SHARE_WRITE -bor [CNativeMethods]::FILE_SHARE_DELETE, 
            [IntPtr]::Zero, [CNativeMethods]::OPEN_EXISTING, 0, [IntPtr]::Zero)

        if ($handle.IsInvalid) {
            throw "Failed to create file handle"
        }

        $moveToHigh = 0
        $success = [CNativeMethods]::SetFilePointerEx($handle, $offset, [ref]$moveToHigh, [EMoveMethod]::Begin)
        if (-not $success) {
            throw "Failed to set file pointer"
        }

        $buffer = New-Object byte[] $size
        $bytesRead = 0
        $success = [CNativeMethods]::ReadFile($handle, $buffer, $size, [ref]$bytesRead, [IntPtr]::Zero)

        if (-not $success) {
            throw "Failed to read file"
        }

        $memoryStream = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
        $gzipStream.Write($buffer, 0, $buffer.Length)
        $gzipStream.Close()

        $compressedBytes = $memoryStream.ToArray()
        $compressedBase64 = [Convert]::ToBase64String($compressedBytes)

        Write-Output $compressedBase64
    } catch {
        Write-Error "An error occurred: $_"
    }

    finally {
        if ($handle -and !$handle.IsInvalid) {
            $handle.Close()
        }
    }
}
