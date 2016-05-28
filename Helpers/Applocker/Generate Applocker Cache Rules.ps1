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
		<Title>Config - Cache Applocker Rules - $($Rule.Name) - Windows</Title>
		<Description><![CDATA[<P>This policy adds a policy to Applocker. Specifically it provides a rule for $($RuleType)</P><br>The rule self describes as: $($Rule.Name)]]></Description>
		<Relevance>Windows of Operating System</Relevance>
		<Relevance><![CDATA[(not exists file (pathname of data folder of client & "\__Global\Applocker\$(Remove-InvalidFileNameChars $Rule.Name).xml"))]]></Relevance>
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

parameter "RuleName"="$(Remove-InvalidFileNameChars $Rule.Name)"
parameter "Storage"="{pathname of data folder of client}\__Global\Applocker"

delete __createfile

createfile until _end_
$($RuleXML)
_end_

folder create "{parameter "Storage"}"

delete "{parameter "Storage"}\{parameter "RuleName"}.xml"
move __createfile "{parameter "Storage"}\{parameter "RuleName"}.xml"

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