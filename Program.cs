using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
using PEAnalyzer.Pe;

namespace PEAnalyzer
{
    internal static class Program
    {
        private static readonly HashSet<string> Commands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "summary",
            "headers",
            "sections",
            "imports",
            "exports"
        };

        private static int Main(string[] args)
        {
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintUsage();
                    return 2;
                }

                if (args.Length == 1 && (IsHelp(args[0]) || args[0].Equals("/?", StringComparison.OrdinalIgnoreCase)))
                {
                    PrintUsage();
                    return 0;
                }

                var parse = ParseArgs(args);
                if (parse.Help)
                {
                    PrintUsage();
                    return 0;
                }
                var pe = PeFile.Load(parse.FilePath);

                switch (parse.Command)
                {
                    case "summary":
                        if (parse.Json)
                        {
                            WriteJson(ToJsonEnvelope(parse, pe, ToJsonSummary(pe)));
                        }
                        else
                        {
                            PrintSummary(pe);
                        }
                        break;
                    case "headers":
                        if (parse.Json)
                        {
                            WriteJson(ToJsonEnvelope(parse, pe, ToJsonHeaders(pe)));
                        }
                        else
                        {
                            PrintHeaders(pe);
                        }
                        break;
                    case "sections":
                        if (parse.Json)
                        {
                            WriteJson(ToJsonEnvelope(parse, pe, ToJsonSections(pe)));
                        }
                        else
                        {
                            PrintSections(pe);
                        }
                        break;
                    case "imports":
                        if (parse.Json)
                        {
                            WriteJson(ToJsonEnvelope(parse, pe, ToJsonImports(pe)));
                        }
                        else
                        {
                            PrintImports(pe);
                        }
                        break;
                    case "exports":
                        if (parse.Json)
                        {
                            WriteJson(ToJsonEnvelope(parse, pe, ToJsonExports(pe)));
                        }
                        else
                        {
                            PrintExports(pe);
                        }
                        break;
                    default:
                        throw new PeFormatException("Unknown command: " + parse.Command);
                }

                return 0;
            }
            catch (PeFormatException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (FileNotFoundException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Unexpected error: " + ex.Message);
                return 1;
            }
        }

        private static bool IsHelp(string value)
        {
            return value != null && (value.Equals("-h", StringComparison.OrdinalIgnoreCase)
                || value.Equals("--help", StringComparison.OrdinalIgnoreCase)
                || value.Equals("help", StringComparison.OrdinalIgnoreCase));
        }

        private static ParsedArgs ParseArgs(string[] args)
        {
            var json = false;
            var positional = new List<string>();
            for (var i = 0; i < args.Length; i++)
            {
                var a = args[i] ?? "";
                if (a.Equals("--json", StringComparison.OrdinalIgnoreCase) || a.Equals("-j", StringComparison.OrdinalIgnoreCase))
                {
                    json = true;
                    continue;
                }

                if (IsHelp(a) || a.Equals("/?", StringComparison.OrdinalIgnoreCase))
                {
                    return new ParsedArgs("summary", "", json, help: true);
                }

                positional.Add(a);
            }

            string command;
            string filePath;

            if (positional.Count == 0)
            {
                throw new PeFormatException("Missing <file> argument.");
            }

            if (Commands.Contains(positional[0]))
            {
                command = positional[0].ToLowerInvariant();
                if (positional.Count < 2)
                {
                    throw new PeFormatException("Missing <file> argument.");
                }
                filePath = positional[1];
            }
            else
            {
                filePath = positional[0];
                command = positional.Count >= 2 ? positional[1].ToLowerInvariant() : "summary";
                if (positional.Count >= 2 && !Commands.Contains(command))
                {
                    throw new PeFormatException("Unknown command: " + positional[1]);
                }
            }

            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new PeFormatException("Missing <file> argument.");
            }

            return new ParsedArgs(command, filePath, json, help: false);
        }

        private static void PrintUsage()
        {
            Console.WriteLine("peanalyze <file> [command]");
            Console.WriteLine("peanalyze [command] <file>");
            Console.WriteLine("peanalyze [--json|-j] <file> [command]");
            Console.WriteLine("peanalyze [--json|-j] [command] <file>");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  summary   Basic file and PE overview (default)");
            Console.WriteLine("  headers   DOS/NT/Optional headers + data directories");
            Console.WriteLine("  sections  Section table");
            Console.WriteLine("  imports   Import table (DLLs and symbols)");
            Console.WriteLine("  exports   Export table (symbols and ordinals)");
            Console.WriteLine();
            Console.WriteLine("Flags:");
            Console.WriteLine("  --json, -j  Output JSON for piping");
        }

        private static void WriteJson(object obj)
        {
            var serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            Console.WriteLine(serializer.Serialize(obj));
        }

        private static Dictionary<string, object> ToJsonEnvelope(ParsedArgs args, PeFile pe, object result)
        {
            var env = new Dictionary<string, object>();
            env["command"] = args.Command;
            env["filePath"] = pe.FilePath;
            env["fileSize"] = pe.FileSize;
            env["result"] = result;
            return env;
        }

        private static Dictionary<string, object> ToJsonSummary(PeFile pe)
        {
            var isDll = (pe.FileHeader.Characteristics & 0x2000) != 0;
            var arch = pe.FileHeader.Machine == 0x8664 ? "x64" : pe.FileHeader.Machine == 0x014c ? "x86" : "0x" + pe.FileHeader.Machine.ToString("X4");

            var dict = new Dictionary<string, object>();
            dict["type"] = isDll ? "DLL" : "EXE";
            dict["arch"] = arch;
            dict["peKind"] = pe.OptionalHeader.IsPE32Plus ? "PE32+" : "PE32";
            dict["subsystem"] = pe.OptionalHeader.Subsystem;
            dict["entryPointRva"] = pe.OptionalHeader.AddressOfEntryPoint;
            dict["imageBase"] = pe.OptionalHeader.ImageBase;
            dict["sectionCount"] = pe.Sections == null ? 0 : pe.Sections.Count;
            dict["importModuleCount"] = pe.Imports == null ? 0 : pe.Imports.Count;
            dict["importSymbolCount"] = pe.Imports == null ? 0 : pe.Imports.Sum(m => m.Symbols.Count);
            dict["exportSymbolCount"] = pe.Exports == null ? 0 : pe.Exports.Symbols.Count;
            return dict;
        }

        private static Dictionary<string, object> ToJsonHeaders(PeFile pe)
        {
            var dict = new Dictionary<string, object>();

            var dos = new Dictionary<string, object>();
            dos["e_lfanew"] = pe.DosHeader.PEHeaderOffset;
            dict["dosHeader"] = dos;

            var fileHeader = new Dictionary<string, object>();
            fileHeader["machine"] = pe.FileHeader.Machine;
            fileHeader["numberOfSections"] = pe.FileHeader.NumberOfSections;
            fileHeader["timeDateStamp"] = pe.FileHeader.TimeDateStamp;
            fileHeader["sizeOfOptionalHeader"] = pe.FileHeader.SizeOfOptionalHeader;
            fileHeader["characteristics"] = pe.FileHeader.Characteristics;
            dict["fileHeader"] = fileHeader;

            var optional = new Dictionary<string, object>();
            optional["magic"] = pe.OptionalHeader.Magic;
            optional["peKind"] = pe.OptionalHeader.IsPE32Plus ? "PE32+" : "PE32";
            optional["addressOfEntryPoint"] = pe.OptionalHeader.AddressOfEntryPoint;
            optional["imageBase"] = pe.OptionalHeader.ImageBase;
            optional["sectionAlignment"] = pe.OptionalHeader.SectionAlignment;
            optional["fileAlignment"] = pe.OptionalHeader.FileAlignment;
            optional["sizeOfImage"] = pe.OptionalHeader.SizeOfImage;
            optional["sizeOfHeaders"] = pe.OptionalHeader.SizeOfHeaders;
            optional["subsystem"] = pe.OptionalHeader.Subsystem;
            optional["dllCharacteristics"] = pe.OptionalHeader.DllCharacteristics;
            dict["optionalHeader"] = optional;

            var dirs = new List<Dictionary<string, object>>();
            for (var i = 0; i < pe.OptionalHeader.DataDirectories.Count; i++)
            {
                var d = pe.OptionalHeader.DataDirectories[i];
                var entry = new Dictionary<string, object>();
                entry["index"] = i;
                entry["name"] = d.Name;
                entry["virtualAddress"] = d.VirtualAddress;
                entry["size"] = d.Size;
                dirs.Add(entry);
            }
            dict["dataDirectories"] = dirs;

            return dict;
        }

        private static List<Dictionary<string, object>> ToJsonSections(PeFile pe)
        {
            var list = new List<Dictionary<string, object>>();
            foreach (var s in pe.Sections)
            {
                var entry = new Dictionary<string, object>();
                entry["name"] = s.Name;
                entry["virtualAddress"] = s.VirtualAddress;
                entry["virtualSize"] = s.VirtualSize;
                entry["pointerToRawData"] = s.PointerToRawData;
                entry["sizeOfRawData"] = s.SizeOfRawData;
                entry["characteristics"] = s.Characteristics;
                list.Add(entry);
            }
            return list;
        }

        private static List<Dictionary<string, object>> ToJsonImports(PeFile pe)
        {
            var list = new List<Dictionary<string, object>>();
            if (pe.Imports == null)
            {
                return list;
            }

            foreach (var m in pe.Imports)
            {
                var module = new Dictionary<string, object>();
                module["name"] = m.Name;

                var symbols = new List<Dictionary<string, object>>();
                foreach (var s in m.Symbols)
                {
                    var sym = new Dictionary<string, object>();
                    sym["isOrdinal"] = s.IsOrdinal;
                    if (s.IsOrdinal)
                    {
                        sym["ordinal"] = s.Ordinal;
                    }
                    else
                    {
                        sym["name"] = s.Name;
                    }
                    symbols.Add(sym);
                }

                module["symbols"] = symbols;
                list.Add(module);
            }

            return list;
        }

        private static Dictionary<string, object> ToJsonExports(PeFile pe)
        {
            var dict = new Dictionary<string, object>();
            if (pe.Exports == null)
            {
                dict["dllName"] = null;
                dict["ordinalBase"] = 0;
                dict["symbols"] = new List<Dictionary<string, object>>();
                return dict;
            }

            dict["dllName"] = pe.Exports.DllName;
            dict["ordinalBase"] = pe.Exports.OrdinalBase;
            var symbols = new List<Dictionary<string, object>>();
            foreach (var s in pe.Exports.Symbols)
            {
                var sym = new Dictionary<string, object>();
                sym["ordinal"] = s.Ordinal;
                sym["functionRva"] = s.FunctionRva;
                sym["name"] = s.Name;
                sym["forwarder"] = s.Forwarder;
                symbols.Add(sym);
            }
            dict["symbols"] = symbols;
            return dict;
        }

        private static void PrintSummary(PeFile pe)
        {
            var isDll = (pe.FileHeader.Characteristics & 0x2000) != 0;
            var arch = pe.FileHeader.Machine == 0x8664 ? "x64" : pe.FileHeader.Machine == 0x014c ? "x86" : "0x" + pe.FileHeader.Machine.ToString("X4");
            var entry = pe.OptionalHeader.AddressOfEntryPoint;
            var imageBase = pe.OptionalHeader.ImageBase;

            Console.WriteLine("File: " + pe.FilePath);
            Console.WriteLine("Size: " + pe.FileSize.ToString(CultureInfo.InvariantCulture) + " bytes");
            Console.WriteLine("Type: " + (isDll ? "DLL" : "EXE"));
            Console.WriteLine("Arch: " + arch + " (" + (pe.OptionalHeader.IsPE32Plus ? "PE32+" : "PE32") + ")");
            Console.WriteLine("Subsystem: " + pe.OptionalHeader.Subsystem);
            Console.WriteLine("EntryPoint RVA: 0x" + entry.ToString("X8"));
            Console.WriteLine("ImageBase: 0x" + imageBase.ToString(pe.OptionalHeader.IsPE32Plus ? "X16" : "X8"));
            Console.WriteLine("Sections: " + pe.Sections.Count.ToString(CultureInfo.InvariantCulture));

            var importModuleCount = pe.Imports == null ? 0 : pe.Imports.Count;
            var importSymbolCount = pe.Imports == null ? 0 : pe.Imports.Sum(m => m.Symbols.Count);
            Console.WriteLine("Imports: " + importModuleCount.ToString(CultureInfo.InvariantCulture) + " modules, " + importSymbolCount.ToString(CultureInfo.InvariantCulture) + " symbols");

            var exportCount = pe.Exports == null ? 0 : pe.Exports.Symbols.Count;
            Console.WriteLine("Exports: " + exportCount.ToString(CultureInfo.InvariantCulture) + " symbols");
        }

        private static void PrintHeaders(PeFile pe)
        {
            Console.WriteLine("DOS Header");
            Console.WriteLine("  e_lfanew: 0x" + pe.DosHeader.PEHeaderOffset.ToString("X8"));
            Console.WriteLine();

            Console.WriteLine("File Header");
            Console.WriteLine("  Machine: 0x" + pe.FileHeader.Machine.ToString("X4"));
            Console.WriteLine("  NumberOfSections: " + pe.FileHeader.NumberOfSections.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("  TimeDateStamp: 0x" + pe.FileHeader.TimeDateStamp.ToString("X8"));
            Console.WriteLine("  SizeOfOptionalHeader: " + pe.FileHeader.SizeOfOptionalHeader.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine("  Characteristics: 0x" + pe.FileHeader.Characteristics.ToString("X4"));
            Console.WriteLine();

            Console.WriteLine("Optional Header");
            Console.WriteLine("  Magic: 0x" + pe.OptionalHeader.Magic.ToString("X4") + " (" + (pe.OptionalHeader.IsPE32Plus ? "PE32+" : "PE32") + ")");
            Console.WriteLine("  AddressOfEntryPoint: 0x" + pe.OptionalHeader.AddressOfEntryPoint.ToString("X8"));
            Console.WriteLine("  ImageBase: 0x" + pe.OptionalHeader.ImageBase.ToString(pe.OptionalHeader.IsPE32Plus ? "X16" : "X8"));
            Console.WriteLine("  SectionAlignment: 0x" + pe.OptionalHeader.SectionAlignment.ToString("X8"));
            Console.WriteLine("  FileAlignment: 0x" + pe.OptionalHeader.FileAlignment.ToString("X8"));
            Console.WriteLine("  SizeOfImage: 0x" + pe.OptionalHeader.SizeOfImage.ToString("X8"));
            Console.WriteLine("  SizeOfHeaders: 0x" + pe.OptionalHeader.SizeOfHeaders.ToString("X8"));
            Console.WriteLine("  Subsystem: " + pe.OptionalHeader.Subsystem);
            Console.WriteLine("  DllCharacteristics: 0x" + pe.OptionalHeader.DllCharacteristics.ToString("X4"));
            Console.WriteLine();

            Console.WriteLine("Data Directories");
            for (var i = 0; i < pe.OptionalHeader.DataDirectories.Count; i++)
            {
                var d = pe.OptionalHeader.DataDirectories[i];
                Console.WriteLine("  " + i.ToString(CultureInfo.InvariantCulture).PadLeft(2) + " " + d.Name.PadRight(18) + " RVA=0x" + d.VirtualAddress.ToString("X8") + " Size=0x" + d.Size.ToString("X8"));
            }
        }

        private static void PrintSections(PeFile pe)
        {
            var rows = new List<string[]>();
            rows.Add(new[] { "Name", "RVA", "VSize", "RawPtr", "RawSize", "Chars" });

            foreach (var s in pe.Sections)
            {
                rows.Add(new[]
                {
                    s.Name,
                    "0x" + s.VirtualAddress.ToString("X8"),
                    "0x" + s.VirtualSize.ToString("X8"),
                    "0x" + s.PointerToRawData.ToString("X8"),
                    "0x" + s.SizeOfRawData.ToString("X8"),
                    "0x" + s.Characteristics.ToString("X8")
                });
            }

            PrintTable(rows);
        }

        private static void PrintImports(PeFile pe)
        {
            if (pe.Imports == null || pe.Imports.Count == 0)
            {
                Console.WriteLine("No imports.");
                return;
            }

            foreach (var module in pe.Imports.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine(module.Name);
                foreach (var sym in module.Symbols)
                {
                    if (sym.IsOrdinal)
                    {
                        Console.WriteLine("  ordinal:" + sym.Ordinal.ToString(CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        Console.WriteLine("  " + sym.Name);
                    }
                }

                Console.WriteLine();
            }
        }

        private static void PrintExports(PeFile pe)
        {
            if (pe.Exports == null || pe.Exports.Symbols.Count == 0)
            {
                Console.WriteLine("No exports.");
                return;
            }

            Console.WriteLine("DLL Name: " + (pe.Exports.DllName ?? "(unknown)"));
            Console.WriteLine("Ordinal Base: " + pe.Exports.OrdinalBase.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine();

            var rows = new List<string[]>();
            rows.Add(new[] { "Ordinal", "RVA", "Name", "Forwarder" });
            foreach (var s in pe.Exports.Symbols.OrderBy(s => s.Ordinal))
            {
                rows.Add(new[]
                {
                    s.Ordinal.ToString(CultureInfo.InvariantCulture),
                    "0x" + s.FunctionRva.ToString("X8"),
                    s.Name ?? "",
                    s.Forwarder ?? ""
                });
            }

            PrintTable(rows);
        }

        private static void PrintTable(List<string[]> rows)
        {
            if (rows == null || rows.Count == 0)
            {
                return;
            }

            var colCount = rows.Max(r => r.Length);
            var widths = new int[colCount];
            for (var c = 0; c < colCount; c++)
            {
                var max = 0;
                foreach (var row in rows)
                {
                    if (row.Length <= c)
                    {
                        continue;
                    }

                    var len = row[c] == null ? 0 : row[c].Length;
                    if (len > max)
                    {
                        max = len;
                    }
                }
                widths[c] = max;
            }

            for (var r = 0; r < rows.Count; r++)
            {
                var row = rows[r];
                for (var c = 0; c < colCount; c++)
                {
                    var cell = row.Length > c ? row[c] ?? "" : "";
                    var pad = widths[c] - cell.Length;
                    Console.Write(cell);
                    if (c != colCount - 1)
                    {
                        Console.Write(new string(' ', pad + 2));
                    }
                }
                Console.WriteLine();

                if (r == 0)
                {
                    for (var c = 0; c < colCount; c++)
                    {
                        Console.Write(new string('-', widths[c]));
                        if (c != colCount - 1)
                        {
                            Console.Write("  ");
                        }
                    }
                    Console.WriteLine();
                }
            }
        }

        private sealed class ParsedArgs
        {
            public ParsedArgs(string command, string filePath, bool json, bool help)
            {
                Command = command;
                FilePath = filePath;
                Json = json;
                Help = help;
            }

            public string Command { get; private set; }
            public string FilePath { get; private set; }
            public bool Json { get; private set; }
            public bool Help { get; private set; }
        }
    }
}
