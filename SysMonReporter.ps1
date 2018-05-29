$ExeMD5Count = @{}
$ExeByIPCount_Src = @{}
$ExeByIPCount_Dst = @{}
$ExeByPortCount_Dst = @{}

function BuildExeMD5CountReport([hashtable]$reportDictionary, $executable, $md5) {
    $key = $md5
    $currentObject = $reportDictionary[$key]
    if ($currentObject -eq $null) {
        $ExeMD5 = New-Object -TypeName PSObject
        $ExeMD5 | Add-Member -MemberType NoteProperty -Name Executable -Value $executable
        $ExeMD5 | Add-Member -MemberType NoteProperty -Name MD5 -Value $md5
        $ExeMD5 | Add-Member -MemberType NoteProperty -Name Tally -Value 1
        $reportDictionary.Add($key,$ExeMD5)
    } else {
        $currentCount = $currentObject.Tally
        $currentCount = $currentCount + 1
        $currentObject.Tally = $currentCount
    }

}

function BuildExeByIPCountReport([hashtable]$reportDictionary, $executable, $ip, $hostname) {
    $key = $executable + "-" + $ip
    $currentObject = $reportDictionary[$key]
    if ($currentObject -eq $null) {
        # create object and add
        $ExeByIPCount = New-Object -TypeName PSObject
        $ExeByIPCount | Add-Member -MemberType NoteProperty -Name Executable -Value $executable
        $ExeByIPCount | Add-Member -MemberType NoteProperty -Name IP -Value $ip
        $ExeByIPCount | Add-Member -MemberType NoteProperty -Name Hostname -Value $hostname
        $ExeByIPCount | Add-Member -MemberType NoteProperty -Name Tally -Value 1
        $reportDictionary.Add($key,$ExeByIPCount)
    } else {
        $currentCount = $currentObject.Tally
        $currentCount = $currentCount + 1
        $currentObject.Tally = $currentCount
    }

}

function BuildExeByPortCount([hashtable]$reportDictionary, $executable, $ip, $port) {
    $key = $executable + "-" + $ip +"-" + $port
    $currentObject = $reportDictionary[$key]
    if ($currentObject -eq $null) {
        # create object and add
        $ExeByPortCount = New-Object -TypeName PSObject
        $ExeByPortCount | Add-Member -MemberType NoteProperty -Name Executable -Value $executable
        $ExeByPortCount | Add-Member -MemberType NoteProperty -Name IP -Value $ip
        $ExeByPortCount | Add-Member -MemberType NoteProperty -Name Port -Value $port
        $ExeByPortCount | Add-Member -MemberType NoteProperty -Name Tally -Value 1
        $reportDictionary.Add($key,$ExeByPortCount)
    } else {
        $currentCount = $currentObject.Tally
        $currentCount = $currentCount + 1
        $currentObject.Tally = $currentCount
    }
}


$events = Get-WinEvent -Filterhashtable @{logname="Microsoft-Windows-Sysmon/Operational";}

$i = 0;
foreach ($event in $events) {
	$x = [xml]$event.ToXml()

    $f = "0-Undefined-Event-ID.txt"

    switch ($x.Event.System.EventID) {
        1 { $f = "0" + $x.Event.System.EventID + "-Process-Creation.txt" 
            BuildExeMD5CountReport([ref]$ExeMD5Count) $x.Event.EventData.Data[3].'#text' $x.Event.EventData.Data[11].'#text'
        }
        2 { $f = "0" + $x.Event.System.EventID + "-Process-Changed-File-Creation.txt" }
        3 { $f = "0" + $x.Event.System.EventID + "-Network-Connection.txt" 
                  
            BuildExeByIPCountReport ([ref]$ExeByIPCount_Src) $x.Event.EventData.Data[3].'#text' $x.Event.EventData.Data[8].'#text' $x.Event.EventData.Data[9].'#text'
            BuildExeByIPCountReport ([ref]$ExeByIPCount_Dst) $x.Event.EventData.Data[3].'#text' $x.Event.EventData.Data[13].'#text' $x.Event.EventData.Data[14].'#text'
            BuildExeByPortCount([ref]$ExeByPortCount_Dst) $x.Event.EventData.Data[3].'#text' $x.Event.EventData.Data[13].'#text' $x.Event.EventData.Data[15].'#text'
            
        }
        4 { $f = "0" + $x.Event.System.EventID + "-Sysmon-Service-State-Changed.txt" }
        5 { $f = "0" + $x.Event.System.EventID + "-Process-Terminated.txt" }
        6 { $f = "0" + $x.Event.System.EventID + "-Driver-Loaded.txt" }
        7 { $f = "0" + $x.Event.System.EventID + "-Image-Loaded.txt" }
        8 { $f = "0" + $x.Event.System.EventID + "-CreateRemoteThread.txt" }
        9 { $f = "0" + $x.Event.System.EventID + "-RawAccessRead.txt" }
        10 { $f = $x.Event.System.EventID + "-ProcessAccess.txt" }
        11 { $f = $x.Event.System.EventID + "-FileCreate.txt" }
        12 { $f = $x.Event.System.EventID + "-RegistryEvent-Create-Delete.txt" }
        13 { $f = $x.Event.System.EventID + "-RegistryEvent-Value-Set.txt" }
        14 { $f = $x.Event.System.EventID + "-RegistryEvent-Rename-KeyValue.txt" }
        15 { $f = $x.Event.System.EventID + "-FileCreateStreamHash.txt" }
        17 { $f = $x.Event.System.EventID + "-PipeEvent-Created.txt" }
        18 { $f = $x.Event.System.EventID + "-PipeEvent-Connected.txt" }
        19 { $f = $x.Event.System.EventID + "-WmiEventFilter-Activity.txt" }
        20 { $f = $x.Event.System.EventID + "-WmiEventConsumer-Activity.txt" }
        21 { $f = $x.Event.System.EventID + "-WmiEventconsumerToFilter-Activity.txt" }
        255 { $f = $x.Event.System.EventID + "-Error.txt" }
        default {}

    }

    $line = $event.ToXml()
    $line | out-file $f -Append
    $i = $i + 1
	
}


$reportTable = New-Object System.Data.DataTable "ExecutableByMD5CountTable"
$reportTable.Columns.Add("Executable", "string") | Out-Null
$reportTable.Columns.Add("MD5", "string") | Out-Null
$reportTable.Columns.Add("Count", "string") | Out-Null
foreach ($k in $ExeMD5Count.Keys) {    
    $row = $reportTable.NewRow()
    $row.Executable = $ExeMD5Count[$k].Executable
    $row.MD5 = $ExeMD5Count[$k].MD5
    $row.Count = $ExeMD5Count[$k].Tally
    $reportTable.Rows.Add($row)

}
$reportTableView = New-Object System.Data.DataView($reportTable)
$reportTableView.Sort = "Executable ASC, MD5 ASC, Count DESC"
$reportTableView | Format-Table -Property Executable,MD5,Count -AutoSize | Out-String -Width 4096 | Out-File "ExeMD5Table.txt"



$reportTable = New-Object System.Data.DataTable "ExecutableBySourceIPCountTable"
$reportTable.Columns.Add("Executable", "string") | Out-Null
$reportTable.Columns.Add("IP", "string") | Out-Null
$reportTable.Columns.Add("Hostname", "string") | Out-Null
$reportTable.Columns.Add("Count", "string") | Out-Null
foreach ($k in $ExeByIPCount_Src.Keys) {    
    $row = $reportTable.NewRow()
    $row.Executable = $ExeByIPCount_Src[$k].Executable
    $row.IP = $ExeByIPCount_Src[$k].IP
    $row.Hostname = $ExeByIPCount_Src[$k].Hostname
    $row.Count = $ExeByIPCount_Src[$k].Tally
    $reportTable.Rows.Add($row)

}
$reportTableView = New-Object System.Data.DataView($reportTable)
$reportTableView.Sort = "Executable ASC, IP ASC, Count DESC"
$reportTableView | Format-Table -Property Executable,IP,Hostname,Count -AutoSize | Out-String -Width 4096 | Out-File "ExeBySrcTable.txt"

$reportTable = New-Object System.Data.DataTable "ExecutableByDestinationIPCountTable"
$reportTable.Columns.Add("Executable", "string") | Out-Null
$reportTable.Columns.Add("IP", "string") | Out-Null
$reportTable.Columns.Add("Hostname", "string") | Out-Null
$reportTable.Columns.Add("Count", "string") | Out-Null
foreach ($k in $ExeByIPCount_Dst.Keys) {    
    $row = $reportTable.NewRow()
    $row.Executable = $ExeByIPCount_Dst[$k].Executable
    $row.IP = $ExeByIPCount_Dst[$k].IP
    $row.Count = $ExeByIPCount_Dst[$k].Tally
    $row.Hostname = $ExeByIPCount_Dst[$k].Hostname
    $reportTable.Rows.Add($row)

}
$reportTableView = New-Object System.Data.DataView($reportTable)
$reportTableView.Sort = "Executable ASC, IP ASC, Count DESC"
$reportTableView | Format-Table -Property Executable,IP,Hostname,Count -AutoSize | Out-String -Width 4096 | Out-File "ExeByDstTable.txt"

$reportTable = New-Object System.Data.DataTable "ExecutableByDestinationPortCountTable"
$reportTable.Columns.Add("Executable", "string") | Out-Null
$reportTable.Columns.Add("IP", "string") | Out-Null
$reportTable.Columns.Add("Port", "string") | Out-Null
$reportTable.Columns.Add("Count", "string") | Out-Null
foreach ($k in $ExeByPortCount_Dst.Keys) {    
    $row = $reportTable.NewRow()
    $row.Executable = $ExeByPortCount_Dst[$k].Executable
    $row.IP = $ExeByPortCount_Dst[$k].IP
    $row.Count = $ExeByPortCount_Dst[$k].Tally
    $row.Port = $ExeByPortCount_Dst[$k].Port
    $reportTable.Rows.Add($row)

}
$reportTableView = New-Object System.Data.DataView($reportTable)
$reportTableView.Sort = "Executable ASC, Port ASC, IP ASC, Count DESC"
$reportTableView | Format-Table -Property Executable,Port,IP,Count -AutoSize | Out-String -Width 4096 | Out-File "ExeByDstPortTable.txt"
