<#
 VIGIX evaluation — TC-05 (PowerShell) benign calibration/simulation. RUN ONLY ON THE DEDICATED TEST WINDOWS MACHINE/VM.
 It runs a harmless Base64-encoded PowerShell command (prints a marker and the date): no network access, no file writes,
 no registry changes, no download. Purpose: produce the Windows PowerShell events that the Wazuh agent forwards, so the
 rule that fires can be calibrated and then evaluated.
 Prerequisites on that machine (yours to set up): Wazuh agent 4.9.2 registered to the manager; Script Block Logging enabled
 (Group Policy "Turn on PowerShell Script Block Logging" or HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging EnableScriptBlockLogging=1);
 agent ossec.conf collects <localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>.
#>
$marker = "vigix-eval-tc05-" + (Get-Date -Format "yyyyMMddHHmmss")
$inner  = "Write-Output '$marker'; Get-Date"
$enc    = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
Write-Host "Running benign encoded command, marker: $marker  (UTC start: $((Get-Date).ToUniversalTime().ToString('o')))"
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc
Write-Host "Done. Tell the evaluator the marker and the agent name."
