Function Remove-InvalidFileNameChars {
<#
.SYNOPSIS
Removes characters considered invalid by the Windows Operating System for file names.

.DESCRIPTION
Takes a string over the pipline or as a parameter and removes invalid characters from the file name.
This sanitization allows you safely take the name you have passed and use it to save a file to disk.

.PARAMETER Name 
A string you wish to escape
#>
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

Function Merge-AppLockerPolicy {
    Param (
        $Policies
    )
    $ExeMethod = ""
    $MsiMethod = ""
    $ScriptMethod = ""
    $AppxMethod = ""

    $ExeRules = ""
    $MsiRules = ""
    $ScriptRules = ""
    $AppXRules = ""

    foreach ($Policy in $Policies) {
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

    $Policy = @"
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
    return $Policy
}

Function New-ApplockerFixlet {
    Param (
        $Type,
        $Name,
        $XML
    )

$Fixlet = @"
<?xml version="1.0" encoding="UTF-8"?>
<BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
	<Fixlet>
		<Title>Config - Cache Applocker Rules - $Type, $Name - Windows</Title>
		<Description><![CDATA[<P>This policy adds a policy to Applocker. Specifically it provides a rule for $Type</P><br>The rule self describes as: $Name]]></Description>
		<Relevance>Windows of Operating System</Relevance>
		<Relevance><![CDATA[(not exists file (pathname of data folder of client & "\__Global\Applocker\$(Remove-InvalidFileNameChars "$Type-$Name").xml"))]]></Relevance>
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

parameter "RuleName"="$(Remove-InvalidFileNameChars "$Type-$Name")"
parameter "Storage"="{pathname of data folder of client}\__Global\Applocker"

delete __createfile

createfile until _end_
<AppLockerPolicy Version="1">
<RuleCollection Type="$Type">
$($XML)
</RuleCollection>
</AppLockerPolicy>
_end_

folder create "{parameter "Storage"}"

delete "{parameter "Storage"}\{parameter "RuleName"}.xml"
move __createfile "{parameter "Storage"}\{parameter "RuleName"}.xml"

]]></ActionScript>
		</DefaultAction>
	</Fixlet>
</BES>
"@
    return $Fixlet
}