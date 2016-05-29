param (
    $OutDir = ".\Output"
)

import-module "$PSScriptRoot\Applocker.psm1" -force

$Policy = Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/EXE and DLL" -EventType Denied, Audited  | New-AppLockerPolicy -RuleType Publisher, Hash, Path -User Everyone 

foreach ($CollectionType in $Policy.RuleCollectionTypes){
    foreach($Rule in $Policy.GetRuleCollection($CollectionType)) {
        $Action = $Rule.Action
        $Name = $Rule.Name
        $Type = $CollectionType
        $ID = $Rule.ID

        $Fixlet = New-AppLockerFixlet -Name $Name -Type $Type -Xml $Rule.ToXML()

        $Fixlet > "$OutDir\$(Remove-InvalidFileNameChars "$Type-$Name.bes")"
    }
}

$Policy = Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/Msi and Script" -EventType Denied, Audited  | New-AppLockerPolicy -RuleType Publisher, Hash, Path -User Everyone 

foreach ($CollectionType in $Policy.RuleCollectionTypes){
    foreach($Rule in $Policy.GetRuleCollection($CollectionType)) {
        $Action = $Rule.Action
        $Name = $Rule.Name
        $Type = $CollectionType
        $ID = $Rule.ID

        $Fixlet = New-AppLockerFixlet -Name $Name -Type $Type -Xml $Rule.ToXML()

        $Fixlet > "$OutDir\$(Remove-InvalidFileNameChars "$Type-$Name.bes")"
    }
}