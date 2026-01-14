#https://eventlogxp.com/blog/advanced-filtering-how-to-filter-events-by-event-descriptions/
$XMLQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[EventData[Data[@Name='SubjectUserName'] and (Data='JohnSmith')]]</Select>
  </Query>
</QueryList>
"@


"SRV1,SRV2,SRV3".Split(",").Split(",") | % {
    Get-WinEvent -ComputerName $_ -FilterXml $XMLQuery -ea 0 | % {
        If ($_.KeywordsDisplayNames -eq "Audit Failure") {
            Write-Host $_.KeywordsDisplayNames -ForegroundColor Yellow
            $_.TimeCreated
            $_.Message
        }
    }
}