using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public static class PeImportAnalyzer
{
    private const int MaxDescriptors = 256;
    private const int MaxThunkEntries = 4096;
    private const int MaxStringScanBytes = 2 * 1024 * 1024;

    public static readonly string[] InjectionApis = { "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "NtCreateThreadEx", "NtMapViewOfSection", "QueueUserAPC", "SetWindowsHookEx", "MapViewOfFile" };
    public static readonly string[] DynamicApis = { "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress" };
    public static readonly string[] NetworkApis = { "InternetOpen", "InternetReadFile", "URLDownloadToFile", "WinHttpOpen", "WinHttpSendRequest", "connect", "WSAStartup" };
    public static readonly string[] ExecutionApis = { "WinExec", "ShellExecute", "CreateProcessA", "CreateProcessW", "system" };
    public static readonly string[] PersistenceApis = { "RegSetValue", "RegCreateKey", "CreateService", "StartService", "OpenSCManager", "SHGetSpecialFolderPath" };
    public static readonly string[] AntiDebugApis = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString" };
    public static readonly string[] CredentialApis = { "CryptProtectData", "CryptUnprotectData", "CredRead", "LsaEnumerateLogonSessions" };

    public static void Analyze(Stream stream, PeAnalysisResult result)
    {
        var pe = result.File;
        if (pe is null) return;

        TryParseImportTable(stream, pe);
        string boundedAscii = Encoding.ASCII.GetString(PeParser.ReadBytes(stream, 0, (int)Math.Min(pe.Length, MaxStringScanBytes)));
        foreach (var api in InterestingApis())
            if (boundedAscii.Contains(api, StringComparison.OrdinalIgnoreCase)) pe.Imports.Add(api);

        pe.ImportCount = pe.Imports.Count;
        if (pe.ImportCount == 0)
        {
            result.Add("Tabela de imports vazia ou não parseável", 1, EvidenceStrength.Low);
            return;
        }

        var injection = Hits(pe, InjectionApis);
        var dynamic = Hits(pe, DynamicApis);
        var network = Hits(pe, NetworkApis);
        var execution = Hits(pe, ExecutionApis);
        var persistence = Hits(pe, PersistenceApis);
        var antiDebug = Hits(pe, AntiDebugApis);
        var credentials = Hits(pe, CredentialApis);

        if (injection.Count >= 2)
            result.Add("Imports de injeção/process memory combinados: " + string.Join(", ", injection), 4, EvidenceStrength.High);
        else if (injection.Count == 1)
            result.Add("Import sensível de memória/processo: " + injection[0], 1, EvidenceStrength.Low);

        if (dynamic.Any(x => x.Contains("LoadLibrary", StringComparison.OrdinalIgnoreCase) || x.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase))
            && dynamic.Any(x => x.Equals("GetProcAddress", StringComparison.OrdinalIgnoreCase) || x.Equals("LdrGetProcedureAddress", StringComparison.OrdinalIgnoreCase)))
            result.Add("Resolução dinâmica de API (LoadLibrary/GetProcAddress)", 2, EvidenceStrength.Medium);

        if (network.Count > 0 && execution.Count > 0)
            result.Add("Imports combinam rede e execução de processo: " + string.Join(", ", network.Concat(execution).Take(8)), 3, EvidenceStrength.Medium);
        else if (network.Count > 0)
            result.Add("Imports de rede presentes: " + string.Join(", ", network), 1, EvidenceStrength.Low);

        if (persistence.Count > 0)
            result.Add("Imports relacionados a persistência/serviços: " + string.Join(", ", persistence), persistence.Count >= 2 ? 2 : 1, EvidenceStrength.Low);
        if (antiDebug.Count > 0)
            result.Add("Imports anti-debug/anti-análise: " + string.Join(", ", antiDebug), 1, EvidenceStrength.Low);
        if (credentials.Count > 0)
            result.Add("Imports relacionados a credenciais/DPAPI: " + string.Join(", ", credentials), 2, EvidenceStrength.Medium);
    }

    private static void TryParseImportTable(Stream stream, PeFile pe)
    {
        if (pe.ImportDirectory.Rva == 0 || pe.ImportDirectory.Size == 0) return;
        if (!pe.TryRvaToOffset(pe.ImportDirectory.Rva, out long descriptorOffset)) return;

        for (int i = 0; i < MaxDescriptors && descriptorOffset + 20 <= pe.Length; i++, descriptorOffset += 20)
        {
            if (!PeParser.ReadUInt32(stream, descriptorOffset, out var originalFirstThunk)
                || !PeParser.ReadUInt32(stream, descriptorOffset + 12, out var nameRva)
                || !PeParser.ReadUInt32(stream, descriptorOffset + 16, out var firstThunk)) return;
            PeParser.ReadUInt32(stream, descriptorOffset + 4, out var timeDateStamp);
            PeParser.ReadUInt32(stream, descriptorOffset + 8, out var forwarderChain);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0 && timeDateStamp == 0 && forwarderChain == 0) break;

            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (!pe.TryRvaToOffset(thunkRva, out long thunkOffset)) continue;
            int thunkSize = pe.Is64Bit ? 8 : 4;
            ulong ordinalMask = pe.Is64Bit ? 0x8000000000000000UL : 0x80000000UL;
            for (int t = 0; t < MaxThunkEntries && thunkOffset + thunkSize <= pe.Length; t++, thunkOffset += thunkSize)
            {
                ulong thunk = pe.Is64Bit
                    ? (PeParser.ReadUInt64(stream, thunkOffset, out var q) ? q : 0)
                    : (PeParser.ReadUInt32(stream, thunkOffset, out var d) ? d : 0);
                if (thunk == 0) break;
                if ((thunk & ordinalMask) != 0) continue;
                if (!pe.TryRvaToOffset((uint)(thunk & 0x7FFFFFFF), out long hintNameOffset)) continue;
                string name = PeParser.ReadAsciiZ(stream, hintNameOffset + 2, 160);
                if (!string.IsNullOrWhiteSpace(name)) pe.Imports.Add(name);
            }
        }
    }

    public static bool HasInjectionPattern(PeFile pe) => Hits(pe, InjectionApis).Count >= 2;
    public static bool HasDynamicResolution(PeFile pe) =>
        pe.Imports.Any(i => i.Contains("LoadLibrary", StringComparison.OrdinalIgnoreCase) || i.Equals("LdrLoadDll", StringComparison.OrdinalIgnoreCase))
        && pe.Imports.Any(i => i.Equals("GetProcAddress", StringComparison.OrdinalIgnoreCase) || i.Equals("LdrGetProcedureAddress", StringComparison.OrdinalIgnoreCase));
    public static bool HasNetworkExecution(PeFile pe) => Hits(pe, NetworkApis).Count > 0 && Hits(pe, ExecutionApis).Count > 0;

    private static List<string> Hits(PeFile pe, IEnumerable<string> apis) => apis.Where(pe.Imports.Contains).Take(8).ToList();
    private static IEnumerable<string> InterestingApis() => InjectionApis.Concat(DynamicApis).Concat(NetworkApis).Concat(ExecutionApis).Concat(PersistenceApis).Concat(AntiDebugApis).Concat(CredentialApis).Distinct(StringComparer.OrdinalIgnoreCase);
}
