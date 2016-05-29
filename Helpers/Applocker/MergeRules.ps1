param (
    $inDir = "C:\Program Files (x86)\BigFix Enterprise\BES Client\__BESData\__Global\Applocker"
)

$Rules = ""

$ExeMethod = ""
$MsiMethod = ""
$ScriptMethod = ""
$AppxMethod = ""

$ExeRules = ""
$MsiRules = ""
$ScriptRules = ""
$AppXRules = ""

foreach ($Ruleset in get-childitem $InDir) {
    if ($Ruleset.Name -eq "Effective.xml") { continue;}

    $xml = select-xml -Path $Ruleset.fullname -XPath "/AppLockerPolicy/RuleCollection"
    
    foreach ($Collection in $XML) {
        
        if ($Collection.Node.Type -eq "Exe") {
            if ($Collection.Node.InnerXml.trim()) {$ExeRules += $Collection.Node.InnerXml.tostring()}
            if ($Collection.Node.EnforcementMode -eq "AuditOnly" -and $ExeMethod -ne "Enabled") { $ExeMethod = 'EnforcementMode="AuditOnly"' }
            if ($Collection.Node.EnforcementMode -eq "Enabled") { $ExeMethod = 'EnforcementMode="Enabled"' }
        }

        if ($Collection.Node.Type -eq "Script") {
            if ($Collection.Node.InnerXml.trim()) {$ScriptRules += $Collection.Node.InnerXml.tostring()}
            if ($Collection.Node.EnforcementMode -eq "AuditOnly" -and $ScriptMethod -ne "Enabled") { $ScriptMethod = 'EnforcementMode="AuditOnly"' }
            if ($Collection.Node.EnforcementMode -eq "Enabled") { $ScriptMethod = 'EnforcementMode="Enabled"' }
        }

        if ($Collection.Node.Type -eq "Msi") {
            if ($Collection.Node.InnerXml.trim()) {$MsiRules += $Collection.Node.InnerXml.tostring()}
            if ($Collection.Node.EnforcementMode -eq "AuditOnly" -and $MsiMethod -ne "Enabled") { $MsiMethod = 'EnforcementMode="AuditOnly"' }
            if ($Collection.Node.EnforcementMode -eq "Enabled") { $MsiMethod = 'EnforcementMode="Enabled"' }
        }

        if ($Collection.Node.Type -eq "AppX") {
            if ($Collection.Node.InnerXml.trim()) {$AppXRules += $Xml.Node.InnerXml.tostring()}
            if ($Collection.Node.EnforcementMode -eq "AuditOnly" -and $AppXMethod -ne "Enabled") { $AppXMethod = 'EnforcementMode="AuditOnly"' }
            if ($Collection.Node.EnforcementMode -eq "Enabled") { $AppXMethod = 'EnforcementMode="Enabled"' }
        }
    }
}



$Rules = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Exe" $ExeMethod>
        $ExeRules
    </RuleCollection>
    <RuleCollection Type="Msi" $MsiMethod>
        $MsiRules
    </RuleCollection>
    <RuleCollection Type="Script" $ScriptMethod>
        $ScriptRules
    </RuleCollection>
    <RuleCollection Type="Appx" $AppxMethod>
        $AppxRules
    </RuleCollection>
</AppLockerPolicy>
"@

$Rules > "$Indir\Effective.xml"