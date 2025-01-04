using legobatman.patches.demotag.Configuration;
using legobatman.patches.demotag.Template;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Memory.Sigscan.Definitions.Structs;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace legobatman.patches.demotag
{
    public partial class Mod : ModBase
    {
        private readonly IModLoader _modLoader;
        private readonly Reloaded.Hooks.Definitions.IReloadedHooks _hooks;
        private readonly ILogger _logger;
        private readonly IModConfig _modConfig;
        private IntPtr _allocatedMemory;
        private string? _charsFilePath;

        private long _ScanNameOffset;

        private string ScanPattern = "66 3B 15 ?? ?? ?? ?? 74 ?? 85 C0 74 ?? F6 40 14 20";  // new code starts at first byte
        private string[] CustomTagNames = [
            "can_place_bombs",
            "has_detonator"
        ];

        public Mod(ModContext context)
        {
            _modLoader = context.ModLoader;
            _hooks = context.Hooks!;
            _logger = context.Logger;
            _modConfig = context.ModConfig;

            _modLoader.ModLoaded += OnModLoaded;
            _modLoader.OnModLoaderInitialized += OnLoaderFinished;

            _modLoader.GetController<IStartupScanner>().TryGetTarget(out var startupScanner);

            startupScanner!.AddMainModuleScan(ScanPattern, OnSigScan);
        }

        private void OnModLoaded(IModV1 modInstance, IModConfigV1 modConfig)
        {
            if (_charsFilePath == null) // check if path hasn't been set yet
            {
                var modPath = _modLoader.GetDirectoryForModId(modConfig.ModId);
                var charsPath = Path.Combine(modPath, "Redirector", "CHARS", "CHARS.TXT"); // Mod/Redirector/CHARS/CHARS.TXT

                if (File.Exists(charsPath))
                {
                    _charsFilePath = charsPath; // found path
                }
                else
                {
                    return;
                }
            }
        }

        private void OnLoaderFinished()
        {
            if (_charsFilePath == null) // no modded chars found, default to vanilla
            {
                string processPath = Environment.ProcessPath ?? string.Empty;
                _charsFilePath = Path.Combine(Path.GetFullPath(Path.Combine(processPath, "..", "CHARS")), "CHARS.TXT");
            }

            LoadDataFromCharsFile(_charsFilePath);
        }

        private void LoadDataFromCharsFile(string? charsFilePath)
        {
            if (string.IsNullOrEmpty(charsFilePath)) // ensure path is defined
            {
                _logger?.WriteLine("charsFilePath is null or empty. Cannot load data.");
                return;
            }

            List<int> CustomTagDataList = new();

            string fileContents = File.ReadAllText(charsFilePath);
            string pattern = @"char_start\s*dir\s*""(?<dir>[^""]+)""\s*file\s*""(?<file>[^""]+)""\s*char_end";

            Regex regex = new(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            MatchCollection matches = regex.Matches(fileContents);

            foreach (Match match in matches)
            {
                string dir = match.Groups["dir"].Value;
                string file = match.Groups["file"].Value;
                string fileName = file + ".txt";

                string? directoryName = Path.GetDirectoryName(charsFilePath);
                if (string.IsNullOrEmpty(directoryName)) // ensure directory can be found
                {
                    continue;
                }

                string fullPath = Path.Combine(directoryName, dir, fileName);

                if (File.Exists(fullPath))
                {
                    LoadAndCheckCustomTags(fullPath, CustomTagNames, CustomTagDataList);
                }
                else
                {
                    // Check vanilla game folder
                    string charsFolderPath = Path.Combine(Path.GetFullPath(Path.Combine(Environment.ProcessPath ?? string.Empty, "..", "CHARS")), dir, fileName);

                    if (File.Exists(charsFolderPath))
                    {
                        LoadAndCheckCustomTags(charsFolderPath, CustomTagNames, CustomTagDataList);
                    }
                    else
                    {
                        // No tag data found
                        CustomTagDataList.Add(0);
                    }
                }
            }

            byte[] byteArray = CustomTagDataList.ConvertAll(b => (byte)b).ToArray();
            AllocateAndWriteMemory(byteArray);
        }

        private static void LoadAndCheckCustomTags(string filePath, string[] customTagNames, List<int> customTagDataList)
        {
            string[] lines = File.ReadAllLines(filePath);
            bool matchFound = false;

            foreach (string line in lines)
            {
                string trimmedLine = line.TrimStart();
                if (trimmedLine.StartsWith(";") || trimmedLine.StartsWith("//"))
                {
                    continue;
                }

                string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1 && Array.Exists(customTagNames, tag => tag.Equals(parts[1], StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                foreach (string tag in customTagNames)
                {
                    if (!line.TrimStart().StartsWith(tag, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (Regex.IsMatch(line, @"\b" + Regex.Escape(tag) + @"\b", RegexOptions.IgnoreCase))
                    {
                        if (Regex.IsMatch(line, $@"\b{tag}\b.*\boff\b(\s|$)", RegexOptions.IgnoreCase))
                        {
                            matchFound = false;
                        }
                        else
                        {
                            matchFound = true;
                        }
                        break;
                    }
                }
            }

            customTagDataList.Add(matchFound ? 1 : 0);
        }

        private void AllocateAndWriteMemory(byte[] data)
        {
            _allocatedMemory = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x1000 | 0x2000, 0x40);

            if (_allocatedMemory == IntPtr.Zero) // couldn't allocate memory
            {
                return;
            }

            Marshal.Copy(data, 0, _allocatedMemory, data.Length);

            byte[] originalBytes = new byte[7];
            var mainModule = Process.GetCurrentProcess().MainModule;
            if (mainModule == null) // failed to get mainModule
            {
                return;
            }

            IntPtr targetAddress = (IntPtr)(mainModule.BaseAddress.ToInt64() + _ScanNameOffset);
            try
            {
                Marshal.Copy(targetAddress, originalBytes, 0, originalBytes.Length);

                string byteString = BitConverter.ToString(originalBytes).Replace("-", "");
            }
            catch (Exception ex)
            {
                _logger?.WriteLine($"{ex.Message}");
                return; // error copying bytes
            }

            string[] ScanAsm =
            [
                $"use32", // keep this line always
                $"push eax",
                $"movzx eax,dx",
                $"add eax,0x{_allocatedMemory.ToInt64():X}",
                $"cmp byte [eax],0x01",
                $"pop eax",
                $"je exit",

                $"originalcode:",
                string.Join("\n", originalBytes.Select(b => $"db 0x{b:X2}")), // Restore original bytes
                $"exit:",
            ];

            if (mainModule != null)
            {
                var hook = _hooks?.CreateAsmHook(ScanAsm, (long)(mainModule.BaseAddress + _ScanNameOffset), AsmHookBehaviour.DoNotExecuteOriginal);
                hook?.Activate();
            }
            else
            {
                return;
            }
        }

        private void OnSigScan(PatternScanResult result)
        {
            _ScanNameOffset = result.Offset;
        }

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        #region Standard Overrides
        public override void ConfigurationUpdated(Config configuration)
        {
            // Apply settings from configuration.
            _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
        }
        #endregion

        #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public Mod() { }
#pragma warning restore CS8618
        #endregion
    }
}