# What a program running as the person can do to the open ABA desktop app.
#
# Run it in the desktop session at medium integrity (an ordinary program) with
# the app open as `aba-app.exe --probe` (elevated). It tries, and reports as
# JSON:
#   - OpenProcess(PROCESS_VM_READ) and a memory read on the app itself and on
#     each WebView2 process it started;
#   - UI Automation: find the page's "Probe button" and Invoke it;
#   - SendInput: click the button and type three keys.
# The app counts clicks and keys that reach its page in
# C:\ProgramData\FileAccessMonitor\app\probe.json (admin-only; read it as
# administrator afterwards). Run it elevated too, as the positive control.
#
# Test helper for the app's phase 0 (VM only); not part of ABA.
# -X/-Y: where to click when UI Automation can't find the button (take them
# from an elevated run's report).
# -Only uia|input: try just one of the two. -Only confirm: open the app's
# native confirm box (through the page, by UI Automation) and try to answer
# Yes with UI Automation and with SendInput.
param([string]$Out = "$env:TEMP\aba-app-probe.json", [int]$X = 0, [int]$Y = 0, [string]$Only = '')

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class P {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string c, string w);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out int pid);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int size);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] b, int n, out IntPtr r);
  [DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr p, IntPtr a, out MBI m, int l);
  [StructLayout(LayoutKind.Sequential)] public struct MBI { public IntPtr Base, AllocBase; public uint AllocProtect; public ushort PartitionId; public IntPtr Size; public uint State, Protect, Type; }
  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx, dy; public uint data, flags, time; public IntPtr extra; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort vk, scan; public uint flags, time; public IntPtr extra; public uint pad1, pad2; }
  [StructLayout(LayoutKind.Explicit)] public struct U { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public U u; }
  public static string TryRead(int pid) {
    IntPtr h = OpenProcess(0x0010 | 0x0400, false, pid); // VM_READ | QUERY_INFORMATION
    if (h == IntPtr.Zero) return "OpenProcess denied (error " + Marshal.GetLastWin32Error() + ")";
    try {
      IntPtr a = IntPtr.Zero; MBI m;
      while (VirtualQueryEx(h, a, out m, Marshal.SizeOf(typeof(MBI))) != 0) {
        if (m.State == 0x1000 && (m.Protect & 0x66) != 0 && (m.Protect & 0x100) == 0) { // committed, readable, not guard
          byte[] b = new byte[64]; IntPtr r;
          if (ReadProcessMemory(h, m.Base, b, b.Length, out r)) return "opened and read " + r + " bytes at 0x" + m.Base.ToString("x");
        }
        a = new IntPtr(m.Base.ToInt64() + m.Size.ToInt64());
      }
      return "opened, nothing read";
    } finally { CloseHandle(h); }
  }
  public static uint Click(int x, int y) {
    SetCursorPos(x, y);
    INPUT[] i = new INPUT[2];
    i[0].type = 0; i[0].u.mi.flags = 0x0002; i[1].type = 0; i[1].u.mi.flags = 0x0004;
    return SendInput(2, i, Marshal.SizeOf(typeof(INPUT)));
  }
  public static uint Keys(string s) {
    INPUT[] i = new INPUT[s.Length * 2];
    for (int k = 0; k < s.Length; k++) { i[2*k].type = 1; i[2*k].u.ki.vk = (ushort)Char.ToUpper(s[k]); i[2*k+1].type = 1; i[2*k+1].u.ki.vk = (ushort)Char.ToUpper(s[k]); i[2*k+1].u.ki.flags = 2; }
    return SendInput((uint)i.Length, i, Marshal.SizeOf(typeof(INPUT)));
  }
}
'@
[P]::SetProcessDPIAware() | Out-Null
$r = [ordered]@{ integrity = (whoami /groups | Select-String 'Mandatory Label\\(\w+)').Matches.Groups[1].Value }
$hwnd = [P]::FindWindow('ABAAppWindow', [NullString]::Value)
if ($hwnd -eq [IntPtr]::Zero) { $r.error = 'app window not found'; $r | ConvertTo-Json | Set-Content $Out; exit 1 }
$appPid = 0; [P]::GetWindowThreadProcessId($hwnd, [ref]$appPid) | Out-Null
$r.app = [ordered]@{ pid = $appPid; memory = [P]::TryRead($appPid) }
$r.webview = @(Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | ? { $_.CommandLine -match 'webview-exe-name=aba-app\.exe' } | % {
  $type = if ($_.CommandLine -match '--type=(\S+)') { $matches[1] } else { 'browser' }
  [ordered]@{ pid = $_.ProcessId; type = $type; memory = [P]::TryRead($_.ProcessId) } })

if ($Only -eq 'confirm') {
  $root = [Windows.Automation.AutomationElement]::FromHandle($hwnd)
  $byName = { param($n) New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, $n) }
  $desk = [Windows.Automation.AutomationElement]::RootElement
  # (UI Automation shows the box under its owner, the app's window.)
  $findDlg = {
    $d = $root.FindFirst([Windows.Automation.TreeScope]::Descendants, (& $byName 'ABA confirm'))
    if (!$d) { $d = $desk.FindFirst([Windows.Automation.TreeScope]::Descendants, (& $byName 'ABA confirm')) }
    $d
  }
  $dlg = & $findDlg
  $c = [ordered]@{ alreadyOpen = [bool]$dlg }
  if (!$dlg) {
    $open = $root.FindFirst([Windows.Automation.TreeScope]::Descendants, (& $byName 'Native confirm'))
    $c.pageButtonFound = [bool]$open
    if ($open) { $open.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke() }
    Start-Sleep 2
    $dlg = & $findDlg
  }
  $c.dialogFound = [bool]$dlg
  if ($dlg) {
    # (Its buttons show up as plain panes: no Invoke pattern for anyone.)
    $yes = $dlg.FindFirst([Windows.Automation.TreeScope]::Descendants, (& $byName 'Yes'))
    $c.yesFound = [bool]$yes
    if ($yes) {
      $yr = $yes.Current.BoundingRectangle
      try { $yes.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke(); $c.yesInvoke = 'no error' } catch { $c.yesInvoke = "failed: $($_.Exception.Message)" }
      Start-Sleep 1
      if (& $findDlg) {
        $c.foregroundSet = [P]::SetForegroundWindow([IntPtr]$dlg.Current.NativeWindowHandle)
        $c.clickSent = [P]::Click([int]($yr.X + $yr.Width / 2), [int]($yr.Y + $yr.Height / 2))
        Start-Sleep 1
      }
      if (& $findDlg) { $c.keysSent = [P]::Keys('y'); Start-Sleep 1 }
    }
  }
  $c.dialogStillOpen = [bool](& $findDlg)
  $r.confirm = $c
  Start-Sleep 1
  $r | ConvertTo-Json -Depth 5 | Set-Content $Out; exit 0
}

# UI Automation
$ua = [ordered]@{}
try {
  $root = [Windows.Automation.AutomationElement]::FromHandle($hwnd)
  $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty, 'Probe button')
  $btn = $root.FindFirst([Windows.Automation.TreeScope]::Descendants, $cond)
  $ua.found = [bool]$btn
  if ($btn) {
    $rect = $btn.Current.BoundingRectangle
    if ($Only -eq 'input') { throw 'skipped' }
    try { $btn.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke(); $ua.invoke = 'no error' } catch { $ua.invoke = "failed: $($_.Exception.InnerException.Message)$($_.Exception.Message)" }
  }
} catch { $ua.note = $_.Exception.Message }
$r.uia = $ua
Start-Sleep 1

# SendInput
if ($Only -eq 'uia') { $r | ConvertTo-Json -Depth 5 | Set-Content $Out; exit 0 }
$si = [ordered]@{ foregroundSet = [P]::SetForegroundWindow($hwnd) }
Start-Sleep -Milliseconds 300
$si.appIsForeground = ([P]::GetForegroundWindow() -eq $hwnd)
if ($rect) { $X = [int]($rect.X + $rect.Width / 2); $Y = [int]($rect.Y + $rect.Height / 2) }
$si.clickAt = "$X,$Y"
if ($X -or $Y) { $si.clickSent = [P]::Click($X, $Y) }
Start-Sleep -Milliseconds 300
$si.keysSent = [P]::Keys('abc')
$r.sendInput = $si
Start-Sleep 1
$r | ConvertTo-Json -Depth 5 | Set-Content $Out
