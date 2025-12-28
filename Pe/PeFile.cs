using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace PEAnalyzer.Pe
{
    internal sealed class PeFile
    {
        private static readonly string[] DataDirectoryNames =
        {
            "Export",
            "Import",
            "Resource",
            "Exception",
            "Security",
            "BaseReloc",
            "Debug",
            "Architecture",
            "GlobalPtr",
            "TLS",
            "LoadConfig",
            "BoundImport",
            "IAT",
            "DelayImport",
            "COMDescriptor",
            "Reserved"
        };

        private PeFile()
        {
        }

        public string FilePath { get; private set; }
        public long FileSize { get; private set; }
        public DosHeaderInfo DosHeader { get; private set; }
        public FileHeaderInfo FileHeader { get; private set; }
        public OptionalHeaderInfo OptionalHeader { get; private set; }
        public List<SectionHeaderInfo> Sections { get; private set; }
        public List<ImportModuleInfo> Imports { get; private set; }
        public ExportInfo Exports { get; private set; }

        public static PeFile Load(string filePath)
        {
            if (filePath == null)
            {
                throw new PeFormatException("Missing file path.");
            }

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found: " + filePath, filePath);
            }

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var br = new BinaryReader(fs, Encoding.ASCII, leaveOpen: true))
            {
                var parser = new Parser(filePath, fs, br);
                return parser.Parse();
            }
        }

        private sealed class Parser
        {
            private readonly string _filePath;
            private readonly FileStream _fs;
            private readonly BinaryReader _br;

            public Parser(string filePath, FileStream fs, BinaryReader br)
            {
                _filePath = filePath;
                _fs = fs;
                _br = br;
            }

            public PeFile Parse()
            {
                var pe = new PeFile();
                pe.FilePath = _filePath;
                pe.FileSize = _fs.Length;

                pe.DosHeader = ReadDosHeader();
                ReadNtHeaders(pe);
                pe.Sections = ReadSectionHeaders(pe.FileHeader.NumberOfSections);
                pe.Imports = ReadImports(pe.OptionalHeader, pe.Sections);
                pe.Exports = ReadExports(pe.OptionalHeader, pe.Sections);

                return pe;
            }

            private DosHeaderInfo ReadDosHeader()
            {
                Seek(0);
                var mz = _br.ReadUInt16();
                if (mz != 0x5A4D)
                {
                    throw new PeFormatException("Not a PE file (missing MZ header).");
                }

                Seek(0x3C);
                var eLfanew = _br.ReadInt32();
                if (eLfanew <= 0 || eLfanew > _fs.Length - 4)
                {
                    throw new PeFormatException("Invalid e_lfanew.");
                }

                return new DosHeaderInfo { PEHeaderOffset = eLfanew };
            }

            private void ReadNtHeaders(PeFile pe)
            {
                Seek(pe.DosHeader.PEHeaderOffset);
                var signature = _br.ReadUInt32();
                if (signature != 0x00004550)
                {
                    throw new PeFormatException("Not a PE file (missing PE signature).");
                }

                var fileHeader = new FileHeaderInfo();
                fileHeader.Machine = _br.ReadUInt16();
                fileHeader.NumberOfSections = _br.ReadUInt16();
                fileHeader.TimeDateStamp = _br.ReadUInt32();
                _br.ReadUInt32();
                _br.ReadUInt32();
                fileHeader.SizeOfOptionalHeader = _br.ReadUInt16();
                fileHeader.Characteristics = _br.ReadUInt16();
                pe.FileHeader = fileHeader;

                pe.OptionalHeader = ReadOptionalHeader(fileHeader.SizeOfOptionalHeader);
            }

            private OptionalHeaderInfo ReadOptionalHeader(ushort sizeOfOptionalHeader)
            {
                var start = _fs.Position;

                var opt = new OptionalHeaderInfo();
                opt.Magic = _br.ReadUInt16();

                if (opt.Magic == 0x10B)
                {
                    opt.IsPE32Plus = false;
                    _br.ReadByte();
                    _br.ReadByte();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.AddressOfEntryPoint = _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.ImageBase = _br.ReadUInt32();
                    opt.SectionAlignment = _br.ReadUInt32();
                    opt.FileAlignment = _br.ReadUInt32();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt32();
                    opt.SizeOfImage = _br.ReadUInt32();
                    opt.SizeOfHeaders = _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.Subsystem = _br.ReadUInt16();
                    opt.DllCharacteristics = _br.ReadUInt16();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    var numDirs = _br.ReadUInt32();
                    opt.DataDirectories = ReadDataDirectories(numDirs);
                }
                else if (opt.Magic == 0x20B)
                {
                    opt.IsPE32Plus = true;
                    _br.ReadByte();
                    _br.ReadByte();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.AddressOfEntryPoint = _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.ImageBase = _br.ReadUInt64();
                    opt.SectionAlignment = _br.ReadUInt32();
                    opt.FileAlignment = _br.ReadUInt32();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    _br.ReadUInt32();
                    opt.SizeOfImage = _br.ReadUInt32();
                    opt.SizeOfHeaders = _br.ReadUInt32();
                    _br.ReadUInt32();
                    opt.Subsystem = _br.ReadUInt16();
                    opt.DllCharacteristics = _br.ReadUInt16();
                    _br.ReadUInt64();
                    _br.ReadUInt64();
                    _br.ReadUInt64();
                    _br.ReadUInt64();
                    _br.ReadUInt32();
                    var numDirs = _br.ReadUInt32();
                    opt.DataDirectories = ReadDataDirectories(numDirs);
                }
                else
                {
                    throw new PeFormatException("Unknown optional header magic: 0x" + opt.Magic.ToString("X4"));
                }

                var expectedEnd = start + sizeOfOptionalHeader;
                if (expectedEnd > start && expectedEnd <= _fs.Length && _fs.Position < expectedEnd)
                {
                    Seek(expectedEnd);
                }

                return opt;
            }

            private List<DataDirectoryInfo> ReadDataDirectories(uint numDirs)
            {
                var count = (int)Math.Min(numDirs, 16u);
                var list = new List<DataDirectoryInfo>(count);
                for (var i = 0; i < count; i++)
                {
                    var rva = _br.ReadUInt32();
                    var size = _br.ReadUInt32();
                    var name = i < DataDirectoryNames.Length ? DataDirectoryNames[i] : "Dir" + i.ToString(CultureInfo.InvariantCulture);
                    list.Add(new DataDirectoryInfo(name, rva, size));
                }

                for (var i = count; i < numDirs; i++)
                {
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                }

                while (list.Count < 16)
                {
                    var name = list.Count < DataDirectoryNames.Length ? DataDirectoryNames[list.Count] : "Dir" + list.Count.ToString(CultureInfo.InvariantCulture);
                    list.Add(new DataDirectoryInfo(name, 0, 0));
                }

                return list;
            }

            private List<SectionHeaderInfo> ReadSectionHeaders(ushort numberOfSections)
            {
                var sections = new List<SectionHeaderInfo>(numberOfSections);
                for (var i = 0; i < numberOfSections; i++)
                {
                    var nameBytes = _br.ReadBytes(8);
                    var name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                    var s = new SectionHeaderInfo();
                    s.Name = name;
                    s.VirtualSize = _br.ReadUInt32();
                    s.VirtualAddress = _br.ReadUInt32();
                    s.SizeOfRawData = _br.ReadUInt32();
                    s.PointerToRawData = _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt32();
                    _br.ReadUInt16();
                    _br.ReadUInt16();
                    s.Characteristics = _br.ReadUInt32();
                    sections.Add(s);
                }
                return sections;
            }

            private List<ImportModuleInfo> ReadImports(OptionalHeaderInfo opt, List<SectionHeaderInfo> sections)
            {
                var dir = opt.DataDirectories[1];
                if (dir.VirtualAddress == 0 || dir.Size == 0)
                {
                    return null;
                }

                var importOffset = RvaToOffset(dir.VirtualAddress, opt.SizeOfHeaders, sections);
                if (importOffset < 0)
                {
                    return null;
                }

                var modules = new List<ImportModuleInfo>();
                var descriptorSize = 20;
                var maxDescriptors = (int)Math.Min(8192u, dir.Size / (uint)descriptorSize);
                for (var i = 0; i < maxDescriptors; i++)
                {
                    var descriptorOffset = importOffset + i * descriptorSize;
                    var descriptor = WithOffset(descriptorOffset, () => new ImportDescriptor
                    {
                        OriginalFirstThunk = _br.ReadUInt32(),
                        TimeDateStamp = _br.ReadUInt32(),
                        ForwarderChain = _br.ReadUInt32(),
                        NameRva = _br.ReadUInt32(),
                        FirstThunk = _br.ReadUInt32()
                    });

                    if (descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 && descriptor.ForwarderChain == 0 && descriptor.NameRva == 0 && descriptor.FirstThunk == 0)
                    {
                        break;
                    }

                    var nameOffset = RvaToOffset(descriptor.NameRva, opt.SizeOfHeaders, sections);
                    if (nameOffset < 0)
                    {
                        continue;
                    }

                    var dllName = ReadAsciiZAtOffset(nameOffset, 4096);
                    if (string.IsNullOrWhiteSpace(dllName))
                    {
                        continue;
                    }

                    var thunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
                    var thunkOffset = RvaToOffset(thunkRva, opt.SizeOfHeaders, sections);
                    if (thunkOffset < 0)
                    {
                        continue;
                    }

                    var module = new ImportModuleInfo { Name = dllName, Symbols = new List<ImportSymbolInfo>() };
                    ReadThunkEntries(module.Symbols, thunkOffset, opt.IsPE32Plus, opt.SizeOfHeaders, sections);
                    modules.Add(module);
                }

                return modules.Count == 0 ? null : modules;
            }

            private void ReadThunkEntries(List<ImportSymbolInfo> symbols, long thunkOffset, bool isPe32Plus, uint sizeOfHeaders, List<SectionHeaderInfo> sections)
            {
                var maxEntries = 1000000;
                for (var i = 0; i < maxEntries; i++)
                {
                    var entryOffset = thunkOffset + (isPe32Plus ? 8L : 4L) * i;
                    if (entryOffset < 0 || entryOffset >= _fs.Length)
                    {
                        break;
                    }

                    if (isPe32Plus)
                    {
                        var value = WithOffset(entryOffset, () => _br.ReadUInt64());
                        if (value == 0)
                        {
                            break;
                        }

                        if ((value & 0x8000000000000000) != 0)
                        {
                            symbols.Add(new ImportSymbolInfo { IsOrdinal = true, Ordinal = (ushort)(value & 0xFFFF) });
                        }
                        else
                        {
                            var nameRva = (uint)(value & 0xFFFFFFFFUL);
                            var nameOffset = RvaToOffset(nameRva, sizeOfHeaders, sections);
                            if (nameOffset < 0)
                            {
                                continue;
                            }
                            var name = ReadImportByNameAtOffset(nameOffset);
                            if (name != null)
                            {
                                symbols.Add(new ImportSymbolInfo { IsOrdinal = false, Name = name });
                            }
                        }
                    }
                    else
                    {
                        var value = WithOffset(entryOffset, () => _br.ReadUInt32());
                        if (value == 0)
                        {
                            break;
                        }

                        if ((value & 0x80000000) != 0)
                        {
                            symbols.Add(new ImportSymbolInfo { IsOrdinal = true, Ordinal = (ushort)(value & 0xFFFF) });
                        }
                        else
                        {
                            var nameOffset = RvaToOffset(value, sizeOfHeaders, sections);
                            if (nameOffset < 0)
                            {
                                continue;
                            }
                            var name = ReadImportByNameAtOffset(nameOffset);
                            if (name != null)
                            {
                                symbols.Add(new ImportSymbolInfo { IsOrdinal = false, Name = name });
                            }
                        }
                    }
                }
            }

            private string ReadImportByNameAtOffset(long nameOffset)
            {
                return WithOffset(nameOffset, () =>
                {
                    _br.ReadUInt16();
                    return ReadAsciiZFromCurrent(4096);
                });
            }

            private ExportInfo ReadExports(OptionalHeaderInfo opt, List<SectionHeaderInfo> sections)
            {
                var dir = opt.DataDirectories[0];
                if (dir.VirtualAddress == 0 || dir.Size == 0)
                {
                    return null;
                }

                var exportOffset = RvaToOffset(dir.VirtualAddress, opt.SizeOfHeaders, sections);
                if (exportOffset < 0)
                {
                    return null;
                }

                var exportDir = WithOffset(exportOffset, () => new ExportDirectory
                {
                    Characteristics = _br.ReadUInt32(),
                    TimeDateStamp = _br.ReadUInt32(),
                    MajorVersion = _br.ReadUInt16(),
                    MinorVersion = _br.ReadUInt16(),
                    NameRva = _br.ReadUInt32(),
                    Base = _br.ReadUInt32(),
                    NumberOfFunctions = _br.ReadUInt32(),
                    NumberOfNames = _br.ReadUInt32(),
                    AddressOfFunctions = _br.ReadUInt32(),
                    AddressOfNames = _br.ReadUInt32(),
                    AddressOfNameOrdinals = _br.ReadUInt32()
                });

                var result = new ExportInfo();
                result.OrdinalBase = exportDir.Base;
                result.Symbols = new List<ExportSymbolInfo>();

                var dllNameOffset = RvaToOffset(exportDir.NameRva, opt.SizeOfHeaders, sections);
                if (dllNameOffset >= 0)
                {
                    result.DllName = ReadAsciiZAtOffset(dllNameOffset, 4096);
                }

                var functionsOffset = RvaToOffset(exportDir.AddressOfFunctions, opt.SizeOfHeaders, sections);
                var namesOffset = RvaToOffset(exportDir.AddressOfNames, opt.SizeOfHeaders, sections);
                var ordinalsOffset = RvaToOffset(exportDir.AddressOfNameOrdinals, opt.SizeOfHeaders, sections);
                if (functionsOffset < 0)
                {
                    return result;
                }

                var maxFunctions = (int)Math.Min(exportDir.NumberOfFunctions, 1000000u);
                var functionRvas = WithOffset(functionsOffset, () =>
                {
                    var arr = new uint[maxFunctions];
                    for (var i = 0; i < maxFunctions; i++)
                    {
                        arr[i] = _br.ReadUInt32();
                    }
                    return arr;
                });

                var funcHasName = new bool[maxFunctions];
                if (namesOffset >= 0 && ordinalsOffset >= 0)
                {
                    var maxNames = (int)Math.Min(exportDir.NumberOfNames, 1000000u);
                    var nameRvas = WithOffset(namesOffset, () =>
                    {
                        var arr = new uint[maxNames];
                        for (var i = 0; i < maxNames; i++)
                        {
                            arr[i] = _br.ReadUInt32();
                        }
                        return arr;
                    });

                    var nameOrdinals = WithOffset(ordinalsOffset, () =>
                    {
                        var arr = new ushort[maxNames];
                        for (var i = 0; i < maxNames; i++)
                        {
                            arr[i] = _br.ReadUInt16();
                        }
                        return arr;
                    });

                    for (var i = 0; i < maxNames; i++)
                    {
                        var funcIndex = nameOrdinals[i];
                        if (funcIndex >= maxFunctions)
                        {
                            continue;
                        }

                        var nameOffset = RvaToOffset(nameRvas[i], opt.SizeOfHeaders, sections);
                        var name = nameOffset >= 0 ? ReadAsciiZAtOffset(nameOffset, 4096) : null;
                        var functionRva = functionRvas[funcIndex];
                        var ordinal = exportDir.Base + funcIndex;
                        var forwarder = ReadForwarderIfAny(functionRva, dir.VirtualAddress, dir.Size, opt, sections);
                        result.Symbols.Add(new ExportSymbolInfo
                        {
                            Ordinal = ordinal,
                            FunctionRva = functionRva,
                            Name = name,
                            Forwarder = forwarder
                        });
                        funcHasName[funcIndex] = true;
                    }
                }

                for (var funcIndex = 0; funcIndex < maxFunctions; funcIndex++)
                {
                    if (funcHasName[funcIndex])
                    {
                        continue;
                    }

                    var functionRva = functionRvas[funcIndex];
                    if (functionRva == 0)
                    {
                        continue;
                    }

                    var ordinal = exportDir.Base + (uint)funcIndex;
                    var forwarder = ReadForwarderIfAny(functionRva, dir.VirtualAddress, dir.Size, opt, sections);
                    result.Symbols.Add(new ExportSymbolInfo
                    {
                        Ordinal = ordinal,
                        FunctionRva = functionRva,
                        Name = null,
                        Forwarder = forwarder
                    });
                }

                return result;
            }

            private string ReadForwarderIfAny(uint functionRva, uint exportDirRva, uint exportDirSize, OptionalHeaderInfo opt, List<SectionHeaderInfo> sections)
            {
                if (functionRva < exportDirRva || functionRva >= exportDirRva + exportDirSize)
                {
                    return null;
                }

                var offset = RvaToOffset(functionRva, opt.SizeOfHeaders, sections);
                if (offset < 0)
                {
                    return null;
                }

                var value = ReadAsciiZAtOffset(offset, 4096);
                if (string.IsNullOrWhiteSpace(value))
                {
                    return null;
                }

                return value;
            }

            private long RvaToOffset(uint rva, uint sizeOfHeaders, List<SectionHeaderInfo> sections)
            {
                if (rva == 0)
                {
                    return -1;
                }

                if (rva < sizeOfHeaders)
                {
                    return rva;
                }

                foreach (var s in sections)
                {
                    var start = s.VirtualAddress;
                    var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                    var end = start + size;
                    if (rva >= start && rva < end)
                    {
                        var delta = rva - start;
                        var offset = (long)s.PointerToRawData + delta;
                        if (offset >= 0 && offset < _fs.Length)
                        {
                            return offset;
                        }
                        return -1;
                    }
                }

                return -1;
            }

            private void Seek(long offset)
            {
                if (offset < 0 || offset > _fs.Length)
                {
                    throw new PeFormatException("Invalid file offset.");
                }
                _fs.Seek(offset, SeekOrigin.Begin);
            }

            private T WithOffset<T>(long offset, Func<T> read)
            {
                var prev = _fs.Position;
                Seek(offset);
                try
                {
                    return read();
                }
                finally
                {
                    Seek(prev);
                }
            }

            private string ReadAsciiZAtOffset(long offset, int maxLen)
            {
                return WithOffset(offset, () => ReadAsciiZFromCurrent(maxLen));
            }

            private string ReadAsciiZFromCurrent(int maxLen)
            {
                var bytes = new List<byte>(Math.Min(maxLen, 256));
                for (var i = 0; i < maxLen && _fs.Position < _fs.Length; i++)
                {
                    var b = _br.ReadByte();
                    if (b == 0)
                    {
                        break;
                    }
                    bytes.Add(b);
                }

                return Encoding.ASCII.GetString(bytes.ToArray());
            }

            private sealed class ImportDescriptor
            {
                public uint OriginalFirstThunk { get; set; }
                public uint TimeDateStamp { get; set; }
                public uint ForwarderChain { get; set; }
                public uint NameRva { get; set; }
                public uint FirstThunk { get; set; }
            }

            private sealed class ExportDirectory
            {
                public uint Characteristics { get; set; }
                public uint TimeDateStamp { get; set; }
                public ushort MajorVersion { get; set; }
                public ushort MinorVersion { get; set; }
                public uint NameRva { get; set; }
                public uint Base { get; set; }
                public uint NumberOfFunctions { get; set; }
                public uint NumberOfNames { get; set; }
                public uint AddressOfFunctions { get; set; }
                public uint AddressOfNames { get; set; }
                public uint AddressOfNameOrdinals { get; set; }
            }
        }
    }
}
