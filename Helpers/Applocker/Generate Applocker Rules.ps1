param (
    $OutputDir = "Output"
)

$global:OutDir = $OutputDir
new-item $global:OutDir -ItemType directory -ErrorAction SilentlyContinue

Function Remove-InvalidFileNameChars {
  param(
    [Parameter(Mandatory=$true,
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true)]
    [String]$Name
  )

  $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
  return ($Name -replace $re)
}

Function Split-Rules { 
    Param (
        [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.PolicyElement] $RuleCollection
    )

    foreach ($Rule in $RuleCollection) {
        $RuleXML = @"
<AppLockerPolicy Version="1">
<RuleCollection Type="$($RuleCollection.RuleCollectionType)">
$($Rule.ToXML())
</RuleCollection>
</AppLockerPolicy>
"@
        New-Fixlet -RuleType $RuleCollection.RuleCollectionType -Rule $Rule -RuleXML $RuleXML
    }

}

Function New-Fixlet {
    Param (
        $RuleType,
        $Rule,
        $RuleXML
    )

$Fixlet = @"
<?xml version="1.0" encoding="UTF-8"?>
<BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
	<Fixlet>
		<Title>Config - Applocker Rules - $($Rule.Name) - Windows</Title>
		<Description><![CDATA[<P>This policy adds a policy to Applocker. Specifically it provides a rule for $($RuleType)</P><br>The rule self describes as: $($Rule.Name)]]></Description>
		<Relevance>Windows of Operating System</Relevance>
		<Relevance>/* If no policies exist we are relevant */
(not exists key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\$($RuleType)" of native registry)

or

/* $($RuleType) Rules */
(not exists key "$($Rule.ID)" of it) of (key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\$($RuleType)" of native registry)</Relevance>
		<Relevance>exists value "EnforcementMode" of key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\$($RuleType)" of native registry /* Do not add rules if no enforcement mechanism is defined as this will cause it to be enforced */</Relevance>
		<Category>Application Whitelisting</Category>
		<Source>Internal</Source>
		<SourceID></SourceID>
		<SourceReleaseDate>2016-05-10</SourceReleaseDate>
		<SourceSeverity></SourceSeverity>
		<CVENames></CVENames>
		<SANSID></SANSID>
		<MIMEField>
			<Name>x-fixlet-modification-time</Name>
			<Value>Tue, 17 May 2016 21:39:44 +0000</Value>
		</MIMEField>
		<Domain>BESC</Domain>
		<DefaultAction ID="Action1">
			<Description>
				<PreLink>Click </PreLink>
				<Link>here</Link>
				<PostLink> to deploy this action.</PostLink>
			</Description>
			<ActionScript MIMEType="application/x-Fixlet-Windows-Shell"><![CDATA[action uses wow64 redirection {not x64 of operating system}

parameter "PowerShellExe"="{ pathname of file ((it as string) of value "Path" of key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" of native registry) }"

delete __createfile
delete applocker.xml

createfile until _end_
$($RuleXML)
_end_

move __createfile Applocker.xml

waithidden "{parameter "PowershellExe"}" -ExecutionPolicy Bypass -command "Import-Module AppLocker;Set-ApplockerPolicy -Merge -XMLPolicy ""{pathname of file "Applocker.xml" of client folder of current site}"""
]]></ActionScript>
		</DefaultAction>
	</Fixlet>
</BES>
"@
    $Output = Remove-InvalidFileNameChars -Name "$($Rule.Name).bes"

    $Fixlet > ".\$($global:OutDir)\$Output"
}

$Policy = Get-AppLockerPolicy -Effective

Split-Rules -RuleCollection $Policy.GetRuleCollection("Exe")
Split-Rules -RuleCollection $Policy.GetRuleCollection("Msi")
Split-Rules -RuleCollection $Policy.GetRuleCollection("Script")
Split-Rules -RuleCollection $Policy.GetRuleCollection("AppX")