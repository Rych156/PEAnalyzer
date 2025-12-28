using System.Collections.Generic;

namespace PEAnalyzer.Pe
{
    internal sealed class DosHeaderInfo
    {
        public int PEHeaderOffset { get; set; }
    }

    internal sealed class FileHeaderInfo
    {
        public ushort Machine { get; set; }
        public ushort NumberOfSections { get; set; }
        public uint TimeDateStamp { get; set; }
        public ushort SizeOfOptionalHeader { get; set; }
        public ushort Characteristics { get; set; }
    }

    internal sealed class OptionalHeaderInfo
    {
        public ushort Magic { get; set; }
        public bool IsPE32Plus { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public ulong ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public uint SizeOfImage { get; set; }
        public uint SizeOfHeaders { get; set; }
        public ushort Subsystem { get; set; }
        public ushort DllCharacteristics { get; set; }
        public List<DataDirectoryInfo> DataDirectories { get; set; }
    }

    internal sealed class DataDirectoryInfo
    {
        public DataDirectoryInfo(string name, uint virtualAddress, uint size)
        {
            Name = name;
            VirtualAddress = virtualAddress;
            Size = size;
        }

        public string Name { get; private set; }
        public uint VirtualAddress { get; private set; }
        public uint Size { get; private set; }
    }

    internal sealed class SectionHeaderInfo
    {
        public string Name { get; set; }
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint SizeOfRawData { get; set; }
        public uint PointerToRawData { get; set; }
        public uint Characteristics { get; set; }
    }

    internal sealed class ImportModuleInfo
    {
        public string Name { get; set; }
        public List<ImportSymbolInfo> Symbols { get; set; }
    }

    internal sealed class ImportSymbolInfo
    {
        public bool IsOrdinal { get; set; }
        public ushort Ordinal { get; set; }
        public string Name { get; set; }
    }

    internal sealed class ExportInfo
    {
        public string DllName { get; set; }
        public uint OrdinalBase { get; set; }
        public List<ExportSymbolInfo> Symbols { get; set; }
    }

    internal sealed class ExportSymbolInfo
    {
        public uint Ordinal { get; set; }
        public uint FunctionRva { get; set; }
        public string Name { get; set; }
        public string Forwarder { get; set; }
    }
}

