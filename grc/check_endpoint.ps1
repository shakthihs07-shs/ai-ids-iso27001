# Read-only check of the operator's admin laptop (ISO/IEC 27001 A.5.17, A.7.7, A.7.9, A.8.1).
# Run in Windows PowerShell:  powershell -File grc\check_endpoint.ps1 > endpoint-YYYY-MM-DD.txt
# Keep the output private: it describes the security state of a personal device. Changes nothing.
param([string]$Key = "$HOME\.ssh\ids_honeypot")

function Get-PowerSeconds($sub, $setting) {
    # AC (plugged in) and DC (battery) values of a power setting, in seconds or as a flag
    powercfg /qh SCHEME_CURRENT $sub $setting | Select-String 'Current (AC|DC) Power Setting Index' |
        ForEach-Object { [Convert]::ToInt32(($_ -split ': ')[1].Trim(), 16) }
}

"# Admin endpoint check, $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Windows version [A.8.8]: $($os.DisplayVersion), build $($os.CurrentBuild).$($os.UBR)"
$hf = Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 1
"Newest installed update [A.8.8]: $($hf.HotFixID) on $($hf.InstalledOn.ToString('yyyy-MM-dd'))"

$bl = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
$state = @{ 0 = 'not available'; 1 = 'on'; 2 = 'off'; 3 = 'encrypting'; 5 = 'suspended' }[[int]$bl]
"Disk encryption on C: [A.7.9]: $state"

$lock = Get-PowerSeconds SUB_NONE CONSOLELOCK
$sleep = Get-PowerSeconds SUB_SLEEP STANDBYIDLE
"Sign-in required on wake [A.7.7]: plugged in $(@('no','yes')[$lock[0]]), battery $(@('no','yes')[$lock[1]])"
"Sleeps (and locks) after [A.7.7]: plugged in $($sleep[0] / 60) min, battery $($sleep[1] / 60) min (0 = never)"

$ssh = "$env:WINDIR\System32\OpenSSH"
& "$ssh\ssh-keygen.exe" -y -P '""' -f $Key *> $null
"Admin SSH key needs a passphrase [A.5.17]: $(if ($LASTEXITCODE -ne 0) { 'yes' } else { 'NO' })"
$agent = Get-Service ssh-agent
"ssh-agent [A.5.17]: $($agent.Status), start $($agent.StartType)"
