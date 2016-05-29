param (
    $OutDir = ".\Output"
)

import-module "$PSScriptRoot\Applocker.psm1" -force

$Policy = Get-AppLockerPolicy -Effective

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