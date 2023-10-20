Write-Host "asr enum - jordanjoewatson"
Write-Host " "

$preferences = Get-MpPreference

# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-abuse-of-exploited-vulnerable-signed-drivers
$uuid_asr_mapping = @{}
$uuid_asr_mapping["7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"] = "Block Adobe Reader from creating child processes"
$uuid_asr_mapping["d4f940ab-401b-4efc-aadc-ad5f3c50688a"] = "Block all Office applications from creating child processes"
$uuid_asr_mapping["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"] = "Block credential stealing from the Windows local security authority subsystem"
$uuid_asr_mapping["be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"] = "Block executable content from email client and webmail"
$uuid_asr_mapping["01443614-cd74-433a-b99e-2ecdc07bfc25"] = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
$uuid_asr_mapping["5beb7efe-fd9a-4556-801d-275e5ffc04cc"] = "Block execution of potentially obfuscated scripts"
$uuid_asr_mapping["d3e037e1-3eb8-44c8-a917-57927947596d"] = "Block JavaScript or VBScript from launching downloaded executable content"
$uuid_asr_mapping["3b576869-a4ec-4529-8536-b80a7769e899"] = "Block Office applications from creating executable content"
$uuid_asr_mapping["75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"] = "Block Office applications from injecting code into other processes"
$uuid_asr_mapping["26190899-1602-49e8-8b27-eb1d0a1ce869"] = "Block Office communication application from creating child processes"
$uuid_asr_mapping["e6db77e5-3df2-4cf1-b95a-636979351e5b"] = "Block persistence through WMI event subscription"
$uuid_asr_mapping["d1e49aac-8f56-4280-b9ba-993a6d77406c"] = "Block process creations originating from PSExec and WMI commands"
$uuid_asr_mapping["b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"] = "Block untrusted and unsigned processes that run from USB"
$uuid_asr_mapping["92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"] = "Block Win32 API calls from Office macros"
$uuid_asr_mapping["c1db55ab-c21a-4637-bb3f-a12568109d35"] = "Use advanced protection against ransomware"

# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide
$rule_value_mapping = @{}
$rule_value_mapping[0] = "Disable"
$rule_value_mapping[1] = "Block"
$rule_value_mapping[2] = "Audit"
$rule_value_mapping[6] = "Warn"

$rule_counts = $preferences.AttackSurfaceReductionRules_Actions.Length 

Write-Host "Attack Surface Reduction Rules found: "
# print out all values for rules found
for ($i = 0; $i -lt $rule_counts ; $i++) {
    $uuid = $preferences.AttackSurfaceReductionRules_Ids[$i] 
    $rule = $uuid_asr_mapping[$uuid] 
    $val = $preferences.AttackSurfaceReductionRules_Actions[$i]
    $strval = $rule_value_mapping[[int]$val] 
    Write-Host "  $uuid, $strval - $val, $rule"
}

Write-Host " "

Write-Host "Attack Surface Reduction Rules not found: "
# print out any rules not found
$missing_rules = @($uuid_asr_mapping.Keys | Where-Object {$_ -notin $preferences.AttackSurfaceReductionRules_Ids})
for ($i = 0; $i -lt $missing_rules.Length; $i++) {
    $rule = $missing_rules[$i]
    $rule_desc = $uuid_asr_mapping[$rule]
    Write-Host "  $rule, $rule_desc"
}
