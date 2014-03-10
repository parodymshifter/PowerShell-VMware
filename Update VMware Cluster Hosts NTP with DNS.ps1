#
# Review and update as needed Domain Search list for each host.
# Review and update as needed DNS server list for each host.
# Review and set all of the NTP providers for all hosts in all connected clusters
# Validate NTP providers, resolve names to allow IP/Name interchangeability
# 
#
Param([switch] $DebugFlag,
	[ValidateRange(0,10)] 
	[int] $DebugLevel = 0,
	[ValidateNotNullOrEmpty()]
	[string]$ParameterFile = "Cluster_Configuration_Defaults.ps1",
	[string]$DataCenter = "*",
	[string]$Cluster = "*",
	[ValidateNotNullOrEmpty()]
	[string]$Add_NTP_Providers,
	[ValidateNotNullOrEmpty()]
	[String]$Remove_NTP_Providers,
	[ValidateSet("off", "on", "automatic")][String]$NTPD_Policy = "on",
	[Switch]$WhatIf = $false
	)
Function Find-Path($Path, [switch]$All=$false, [Microsoft.PowerShell.Commands.TestPathType]$type="Any")
{
## You could  comment out the function stuff and use it as a script instead, with this line:
# param($Path, [switch]$All=$false, [Microsoft.PowerShell.Commands.TestPathType]$type="Any")
   if($(Test-Path $Path -Type $type)) {
      return $path
   } else {
      [string[]]$paths = @($pwd); 
      $paths += "$pwd;$env:path".split(";")
      
      $paths = Join-Path $paths $(Split-Path $Path -leaf) | ? { Test-Path $_ -Type $type }
      if($paths.Length -gt 0) {
         if($All) {
            return $paths;
         } else {
            return $paths[0]
         }
      }
   }
   throw "Couldn't find a matching path of type $type"
}
Set-Alias find Find-Path

$ScriptPath = (Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path)
Write-Host "`$parameterfile: $ParameterFile, `$ScriptPath: $ScriptPath"
if ( test-path -Include ${ParameterFile} -Path ${ScriptPath}\*.ps1 ) {
	Write-Host "`$parameterfile: $parameterfile, `$ScriptPath: $ScriptPath"
	$Parameter_Defaults = Get-ChildItem  -File -Path ${ScriptPath}\*.ps1 -Include ${parameterfile}
	$Parameter_Directory = $Parameter_Defaults.DirectoryName
	if ( ${Parameter_Defaults} ) { 
		$Parameter_Defaults
		$Parameter_Defaults.Directory
		$Parameter_Defaults.DirectoryName
		. $Parameter_Defaults 
		}
	else { 
	  Write-Error -ErrorAction Stop -RecommendedAction "Create $parameterfile or specify `$parameterfile in call" -Category ObjectNotFound -Message "No parameter file found: $parameterfile "
	  }
	}
else {
	Write-Error -ErrorAction Stop -RecommendedAction "Create $parameterfile or specify `$parameterfile in call" -Category ObjectNotFound -Message "No parameter file found: $parameterfile "
}
$Author = "Robert Boyd"
$Version = 1.0
$Title="Update Cluster Hosts NTP and DNS settings"
$Description = "Review and set all of the NTP providers for all hosts in all connected clusters"
Import-Module DnsShell
# Change history:
# 2013-06-27	R. Boyd		Initial version based on example code by http://networkfu.com/staff/joe-monaghan/
#							and Al Feersum ( http://blog.forrestshields.com/post/2012/08/01/Resolving-Reverse-DNS-Lookups-in-PowerShell.aspx )
#
# 2013-07-03	R. Boyd		cross check IP/name strings against DNS for matches
# 2013-07-08	R. Boyd		Add Austin and Waltham & Debug ( fixed Time calc and cluster selection) 
# 2013-07-08	R. Boyd		Change Debug/Whatif mode to -WhatIf parameter control, clean up output, debug 
# 2013-07-16	R. Boyd		Gather parameters from script 
# 2013-11-18	R. Boyd		Add ntpd policy set/start when detecting time is off.
#----------------------------------------------------------------------------
# Use the user's selected colors for debug output
#
$a = (Get-Host).PrivateData

$DebugFG = $a.DebugForegroundColor
$DebugBG = $a.DebugBackgroundColor

#
$global:allowedDifferenceSeconds = 120
#
# Create the hash table of Network Settings for each Data Center/Cluster pair.   Please see the example below.  This
# hash table can also be put into a separate script, by default named Cluster_Configuration_Defaults.ps1 and placed in
# the same directory as this script.
#
#$Network_Settings = 
#@(
#  [pscustomobject]@{Name="DC1_Cluster1";DNS=@("1.2.3.4", "5.6.7.8");
#  	NTP="blank separated list of names or IP addresses e.g router-core.yourcompany.com";
#  	Domain="yourcompany.com";SearchDomain=@("yourcompany.com", "internaldomain.com")},
#  [pscustomobject]@{Name="DC2_Cluster2";DNS=@("10.11.12.13", "13.14.15.16", "17.18.19.20");
#  	NTP="a.b.c 0.us.ntp.0.us.pool.ntp.org 1.us.pool.ntp.org 2.us.pool.ntp.org";
#  	Domain="localdomain.mycompany.com";SearchDomain=@("localdomain.mycompany.com", "internaldomain2.com")},
#  )
#
# Functions
#
Function Debug-Output  
  {
   Param(
	 [Parameter(Mandatory=$True,Position=1)]
	 [ValidateRange(0,10)][int]$Level, 
	 [Parameter(Mandatory=$True,Position=2)]
	 [string]$Message 
	)
#
# Print Debug output 
#
	if ( $DebugFlag ) { if ($Level -le $DebugLevel ) {
			
		Write-Host -ForegroundColor $DebugFG -BackgroundColor $DebugBG "Debug L${Level}($DebugLevel) $Message" 
		# -WarningAction Continue -ErrorAction Continue
		$WhereFrom = $MyInvocation.ScriptName 
		$WhereAt = $Myinvocation.ScriptLineNumber 
		Write-Host -ForegroundColor $DebugFG -BackgroundColor $DebugBG "From: $WhereFrom Line: $WhereAt "
		}
	}
}
Function CheckHostDateTime ( $testHost ) {
    
    #get host datetime system
    $dts = get-view $testHost.ExtensionData.configManager.DateTimeSystem
    
    #get host time (sometimes DateTimeSystem returns more than 1 value.  Only use the 1st one)
    $t = $dts[0].QueryDateTime()
	Write-Host "Time on " $testHost $t "(UTC)" 
    
    #calculate time difference in seconds
    Try { 
		$s = ( $t - [DateTime]::UtcNow).TotalSeconds 
	    $v = [Math]::Floor([math]::abs($s))
		
        Debug-Output 1 "`$t: $t, `$s: $s"
		Debug-Output 1 "`$v: $v"
		Debug-Output 1 "`$allowedDifferenceSeconds: $allowedDifferenceSeconds"
    #check if time difference is too much
	    if( $v -gt $allowedDifferenceSeconds ) {
		Write-Warning -Message "Time on $testHost outside allowed range( ${v} Sec)"
        #print host and time difference in seconds
        $row = "" | select HostName, Seconds
        $row.HostName = $testHost
        $row.Seconds = $s
		 
        $row
      }
	  else{
        Write-Host "Time on" $testHost "within allowed range"
      }
	}
		Catch { Write-Warning -Message "Time difference calculation failed for $testHost"
			Debug-Output 0 "`$testHost: $testHost"
			Write-Debug "`$t: $t " 
			$dts
			}
}
#
# Check time on VM Guests
Function Get-VMGuest-NTP-status {
  Param( [string]$VMguestmachine )
  $ntp_status = (Invoke-VMScript -ScriptText "/usr/sbin/ntptrace -m 1" -VM $VMguestmachine -GuestUser engadmin -GuestPassword Welcome2Linux )
  [decimal] $ntp_offset_s = ( ntp_status.split(",").trim() -match "offset").split(" ")[1]
  $ntp_ok = [Math]::Floor($ntp_offset_s) -lt 1000 

  $ntpq_status = (Invoke-VMScript -ScriptText "/usr/sbin/ntpq -p" -VM $VMguestmachine -GuestUser engadmin -GuestPassword Welcome2Linux )
  [decimal] $ntpq_offset_ms = (($ntpq_status.split("|")).split("*")[1] -replace "\s+", " ").split(" ")[8]
  $ntpq_ok = [Math]::Floor($ntp_offset_ms/1000) -lt 1000 
  Return ( $ntp_ok -or $ntpq_ok )
 }
 #
 # Resolve an IP/DNS address
 #
Function ResolveAddress {

    Param(
		[string]$IP, 
		[string]$Server
		)    
	[bool]$IPv6 = ($IP -match "^[a-z0-9][a-z0-9][a-z0-9][a-z0-9]::")    
	[bool]$Server_IPv6 = ($Server -match "^[a-z0-9][a-z0-9][a-z0-9][a-z0-9]::")
	$Resolved = @()
	Debug-Output  5 " IP: $IP, Server: $Server " 
	try { if ( $Server) { 
		$DNS_result = get-Dns $IP -Server $Server 
		if ( ! $DNS_result.answer -match "\S" ) { $DNS_result = get-Dns $IP }
		} 
		else { $DNS_result = get-Dns $IP }
		Debug-Output  5 "`$DNS_result:  $DNS_result.answer" 
		if ( $DNS_result.answer.IPAddress.IPaddressTostring -match "\S" ) 
			{ 
			  $HostIP = $DNS_result.answer.IPAddress.IPaddressTostring
			 Debug-Output 5 "`$HostIP: $HostIP" 
			  if ( ! $HostIP ) {$HostIP = $IP} 
			  else { $HostName = $IP }
			  }
		else { $HostIP = $IP }
		Debug-Output  5 "`$Host_IP: ${Host_IP}" 
		if ( $DNS_result.answer.HostName -match "\S"  ) { $HostName = $DNS_result.answer.HostName.trim(".") }
		else { $HostName = $IP }
		Debug-Output 5 "`$HostIP: $HostIP, `$HostName: $HostName" 
		if ( $HostName -contains $HostIP ) { $Resolved = "Unable to resolve"  } 
		else {
	  		$Resolved = @( $HostIP, $HostName ) }
	 	Debug-Output  5 "`$Resolved: $Resolved" 
	}
	Catch {
    try { $IPinfo = ([system.net.dns]::GetHostEntry($IP))
		$hostName = $IPinfo.HostName
		$HostIP = $IPinfo.IPaddressToString
		 if ( $hostName -contains $HostIP ) { 
		  $Resolved = "Unable to resolve"
		 }
		 else
		 {
		   $Resolved = @( $HostName, $HostIP )
		   }
		}
    catch {
        try {
            if (-not($IPv6)) {
            try { 
			  $HostIP = ([system.net.dns]::GetHostEntry($IP)).IPAddressToString
        	  $Resolved = @( $IP, $HostIP )
			  }
			catch { 
				  $IPinfo = &nslookup -timeout=1 $IP 2>$null
				  
                  $HostName = ($IPinfo |where {$_ -match "^Name:"}).split(':')[1].trim()
				  if ( $hostName -notcontains $IP ) { 
				  	$Resolved = @( $HostName, $IP ) }
					else { $HostIP = ($IPinfo |where {$_ -match "^Address:"}).split(':')[1].trim() 
					       $Resolved = @( $IP, $HostIP )
					}
				   Debug-Output 5 "Resolved with nslookup:  $Resolved" 	
				  }
            } else {
                $Resolved = "Unresolvable v6 local address"
            }
        }
        catch { $Resolved = "Unable to resolve" }
	  }
    }
	$rcount = $Resolved.Count
	$rend = $Resolved[$rcount]
	Debug-Output  5 " Resolved: `[ 0..${Rcount} `] ${Rend}"
	
    return $Resolved 

}

$borderline = "-"*50
Debug-Output 1 "`$DebugFlag: $DebugFlag `$DebugLevel: $DebugLevel"

$DataCenter_Param = $DataCenter
$Cluster_Param = $cluster
$MY_WhatIf = $WhatIf

Debug-Output 0 "`$DataCenter_Param: $DataCenter_Param, `$Cluster_Param: $Cluster_Param, `$MY_WhatIf: $MY_WhatIf"

Write-Host "Checking NTP provider settings for all hosts"

if ( $DebugFlag ) { 
	Write-Host $borderline
	Debug-Output 0 "`$DNS_Table - Hash Table of DNS Servers by DC/Cluster"
	[Collections.SortedList]$DNS_Table 
	Write-Host $borderline
	Debug-Output 0 "`$NTP_Table - Hash Table of NTP Providers by DC/Cluster"
	[Collections.SortedList]$NTP_Table 
	}
foreach ($Data_Center in ( Get-Datacenter -Name $DataCenter_Param | Sort-Object Name ))
{ 
  Write-Host $borderline
  Write-Host "Visiting Data Center: " $Data_Center.Name
foreach ($Cluster in (Get-Cluster -Location $Data_Center -Name $Cluster_Param | Sort-Object Name))
{ 
  Debug-Output 0 "`$Cluster: $Cluster"
  $DC_Cluster_Name = $Data_Center.Name+"_"+$Cluster
  Debug-Output  0 "Cluster: $Cluster, `$DC_Cluster_name $DC_Cluster_Name"
  $Cluster_Network_Settings = ( $Network_Settings | Where-Object Name -eq $DC_Cluster_Name )
  $Cluster_Network_Settings
  Write-Host "Client Version: " (Get-Cluster $Cluster -Location $Data_Center | Get-View).client.Version
  if ( ! $Cluster_Network_Settings) {
  	Write-Error -Category ObjectNotFound  -Message "No Network Settings specified for $DC_Cluster_Name" -RecommendedAction "Edit the `$Network_Settings to include this cluster." -ErrorAction Inquire
  }
  else
  {
  # $DNS_params = ($DNS_Table[ $DC_Cluster_Name ]).Trim()
  $DNS_parray = ($Cluster_Network_Settings.DNS) 
  $DNS_params = $DNS_parray -join " "
  # 
  Write-Host $borderline
  Write-Host "DNS Providers for Data Center ${Data_Center} Cluster ${Cluster}: $DNS_params"
  #
  # $NTP_params = ($NTP_Table[ $DC_Cluster_Name ]).Trim()
  $NTP_params = ($Cluster_Network_Settings.NTP).Trim()
  Write-Host "NTP Providers for Data Center ${Data_Center} Cluster ${Cluster}: $NTP_params"
  Write-Host $borderline
  $NTP_parray = $NTP_params.split(" ")
  if ( $Add_NTP_Providers ) { $NTP_parray += ($Add_NTP_Providers.Trim()).split(",") }
  if ( $DebugFlag ) { Debug-Output 1 "`$NTP_parray" 
  		if ( $DebugLevel -ge 1 ) { $NTP_parray } }
  $NTP_carray = $NTP_parray # Copy the array 
  #
  # For each specified NTP provider verify that it exists and check for name/IP address
  # Build array of regex singles or pairs
  #
  foreach ($NTP_address in $NTP_parray )
  {
     if ($DebugFlag ) { Debug-Output 1 "`$NTP_parray" 
	 			if ( $DebugLevel -ge 1 ) { $NTP_parray } }
  # See if the provider is actually on the network.  If not, ignore it and delete from the active list
     if ( ( ( ping -n 1 -l 1480 $NTP_address ) -contains "timed out." )  )
      { 
	    Write-Host "NTP Provider $NTP_address is not reachable "
		[array]$NTP_parray = $NTP_parray -notmatch $NTP_address
		[array]$NTP_carray = $NTP_carray -notmatch $NTP_address
	  }
	  else
	   { 
	   # Replace the existing record with both forms of the address
	     $NTP_address_alternate = ResolveAddress $NTP_address $DNS_parray[0]
		 Debug-Output  1 "`$NTP_address_alternate: $NTP_address_alternate" 
		 if ( ($NTP_address_alternate -notcontains "Unable to resolve") -and
		 	( $NTP_address_alternate[0] -and $NTP_address_alternate[1] ) )
		 { 
		 # the lookup resolved, put both forms of address in the list for matching
		 Debug-Output  1 "NTP address alternate: $NTP_address_alternate" 
		 $NTP_parray =  $NTP_parray -notmatch $NTP_address 
	     [array]$NTP_parray += "("+[regex]::escape($NTP_address_alternate[0])+"|"+[regex]::escape($NTP_address_alternate[1])+")"
		 }
		 # Only one available
		 else { [array]$NTP_parray += [regex]::escape($NTP_address) }
		}
	}  
  [regex] $NTP_providers_regex = ‘(?i)^(‘ + ( $NTP_parray  –join “|” ) + ‘)$’
  Debug-Output  1 "The regular expression for matching preferred NTP providers:
  				$NTP_providers_regex.tostring() " 
  #
  # For each connected host in the current cluster get the current "Old" NTP providers and compare to specified
  #
  $Hosts = Get-Cluster $Cluster -Location $Data_Center  | Get-VMHost -State connected | Where-Object { ( $_.ConnectionState -eq "Connected") -and ($_.PowerState -EQ "PoweredOn")} | Sort-Object Name
  
  if ( $Hosts ) {
  ForEach ($nxtHost in $Hosts) 
  {
   Write-Host $borderline
   Write-Host "Host.Name: " $nxtHost.Name ", Host.Version: " $nxtHost.Version
   CheckHostDateTime $nxtHost
   # Check the network settings 
   $Host_Network = Get-VMHostNetwork -VMHost $nxtHost | `
 	select HostName,DnsAddress,DomainName,SearchDomain
	$DNS_diff = Compare-Object -ReferenceObject $Cluster_Network_Settings.DNS -DifferenceObject $Host_Network.DnsAddress
		  
	if ( $DNS_diff ) { 
		Write-Warning -Message "DNS server list does not match master reference.  Please verify"
		
		if ( $Domain_Add = ($DNS_diff | where SideIndicator -eq "<=" ).InputObject ) {
			Write-Warning -Message "Add these:"
			$Domain_Add
			}
		
		if ( $Domain_Remove = ($DNS_diff | where SideIndicator -ne "<=" ).InputObject ) {
			Write-Warning -Message "Remove these:"
			$Domain_Remove
			}
			$Reference_DNS = $Cluster_Network_Settings.DNS
			Write-Warning -Message "Setting DNS Servers to:"
			$Reference_DNS
			Get-VMHostNetwork -VMHost $nxtHost | Set-VMHostNetwork -DNSAddress $Reference_DNS -WhatIf:$MY_WhatIf | Out-Null
		}
	
	if ( $Host_Network.SearchDomain ) {
		[array]$Search_Domain_diff = Compare-Object -ReferenceObject $Cluster_Network_Settings.SearchDomain -DifferenceObject $Host_Network.SearchDomain
	   }
	 else {
	    [array]$Search_Domain_diff = Compare-Object -ReferenceObject $Cluster_Network_Settings.SearchDomain -DifferenceObject @(" ")
	  }
	  
	if ( $Search_Domain_diff ) { 
		Write-Warning -Message "Search Domain list does not match master reference.  Please verify"
		if ( $Search_Domain_Add = ($Search_Domain_diff | where SideIndicator -eq "<=").InputObject ) {
			Write-Warning -Message "Add these:"
			$Search_Domain_Add
			}
		
		if ( $Search_Domain_Remove = ($Search_Domain_diff | where SideIndicator -ne "<=" ).InputObject ) {
			Write-Warning -Message "Remove these:"
			$Search_Domain_Remove
			}
			$Reference_Search_Domain = $Cluster_Network_Settings.SearchDomain
			Write-Warning -Message "Setting search domains to"
			$Reference_Search_Domain
			Get-VMHostNetwork -VMHost $nxtHost | Set-VMHostNetwork -SearchDomain $Reference_Search_Domain -WhatIf:$MY_WhatIf | Out-Null
		}
	  
	if ( $Cluster_Network_Settings.Domain -ne $Host_Network.DomainName ) {
	    $Error_domain = $Host_Network.DomainName
		$Reference_domain = $Cluster_Network_Settings.Domain
		if ( $Error_domain ) {
		Write-Warning -Message "Domain name on host: $Error_Domain does not match reference value: $Reference_domain "
		 } else {
		 Write-Warning -Message "No Domain name on host, does not match reference value: $Reference_domain "
		 Get-VMHostNetwork -VMHost $nxtHost | Set-VMHostNetwork -DomainName $Reference_domain -WhatIf:$MY_WhatIf | Out-Null
		 }
		}
   if ( $NTP_params -and ( $nxtHost.PowerState -eq "PoweredOn" ) ) 
   { 
    $reset = 0
	$Old_NTP_providers = Get-VMHostNtpServer -VMHost $nxtHost
	
	[array]$old_NTP_parray = $Old_NTP_providers
	Debug-Output  1 "Configured NTP providers: "
	if ($DebugFlag) { if ( $DebugLevel -ge 1 ) {$old_NTP_parray } }
	
    foreach ($NTP_address in $old_NTP_parray )
    {
	  # Replace the existing record with regex escaped form(s) of the address
	  $old_NTP_parray =  $old_NTP_parray -notmatch $NTP_address 
	  $NTP_address_alternate = ResolveAddress $NTP_address $DNS_parray[0]
	  if ( ($NTP_address_alternate -notcontains "Unable to resolve") -and
	  		( $NTP_address_alternate[0] -and $NTP_address_alternate[1] ) )
		 { # the lookup resolved, put both forms of address in the list for matching
	     [array]$old_NTP_parray += "("+[regex]::escape($NTP_address_alternate[0])+"|"+[regex]::escape($NTP_address_alternate[1])+")"
		 }
		 else { [array]$old_NTP_parray += [regex]::escape($NTP_address) 
		 }	
	}
	[regex] $NTP_old_providers_regex = ‘(?i)^(‘ + ( $Old_NTP_parray –join “|” )  + ‘)$’
    Debug-Output  1 "The regular expression for matching previous NTP providers: $NTP_old_providers_regex.tostring() " 
    
	# $NTP_Providers_diff = Compare-Object -ReferenceObject $Current_NTP_providers -DifferenceObject $NTP_parray
	# Compare-Object didn't work out since it doesn't do regex pattern matching 
	
	[array]$NTP_Providers_add = [array]$NTP_carray -notmatch $NTP_old_providers_regex
	[array]$NTP_Providers_remove = [array]$Old_NTP_providers -notmatch $NTP_providers_regex
	 if ( $Remove_NTP_Providers ) { [array]$NTP_providers_remove += ($Remove_NTP_Providers.Trim()).split(",") }
	 
	if ( $NTP_Providers_add -or $NTP_Providers_remove ) {
		$reset = 1
		Write-Host "Host: $nxtHost, NTP Providers: $Old_NTP_providers"
		}
	if ( $NTP_Providers_add ) {
	  Write-Warning -Message "Host $nxtHost needs these NTP providers added: $NTP_Providers_add"
      # Add each provider not already in the list
      ForEach ($NTP_provider in $NTP_Providers_add )
	  {
	    # $NTP_address = $NTP_provider.InputObject
	    Write-Host "Updating $nxtHost NTP with $NTP_provider "
		Add-VmHostNtpServer -NtpServer "$NTP_provider" -VMHost $nxtHost -WhatIf:$MY_WhatIf | Out-Null 
       }
	  }
     
	 if ( $NTP_Providers_remove ) {
	   Write-Warning -Message "Host $nxtHost needs these NTP providers removed: $NTP_Providers_remove"
	   ForEach ( $NTP_remove in $NTP_Providers_remove )
	   # Remove NTP provider not conforming to the master list
       { 
	     Write-Host "Removing NTP reference $NTP_remove from $nxtHost"
		 Remove-VmHostNtpServer -NtpServer "$NTP_remove" -VMHost $nxtHost -Confirm:$false -WhatIf:$MY_WhatIf | Out-Null 
       }
	 }
	 
	 $host_ntp_service = Get-VMHostService -VMhost $nxtHost | where { $_.key -eq 'ntpd' } 
	 
	 if ( ( $host_ntp_service.Policy -ne $NTPD_Policy ) -or ( -not $host_ntp_service.Running ) ) 
	 { 
	   $reset = 1 
	   Write-Host "NTP service not running or policy not set to $NTPD_Policy" 
	   } 
    if ( $reset -ne 0 ) # -and ( -not $DEBUGFLAG ) ) 
	{ 
	  Get-VmHostService -VMHost $nxtHost | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -Policy $NTPD_Policy -WhatIf:$MY_WhatIf | Out-Null
	  Get-VmHostService -VMHost $nxtHost | Where-Object {$_.key -eq "ntpd"} | Restart-VMHostService -Confirm:$false -WhatIf:$MY_WhatIf | Out-Null
      write-host "NTP Server(s) changed on $nxtHost, service restarted"
	  write-host "NTP providers for ${nxtHost}: " (Get-VMHostNtpServer -VMHost $nxtHost)
	  # See how the time is doing now
	  CheckHostDateTime $nxtHost
	  }
	 else
	 {
	  write-host "NTP providers for ${nxtHost} are current."
	  }
   }
  } 
 }
 else {
 	Write-Host "Cluster ${DC_Cluster_Name} has no connected VM Hosts that are powered on."
 }
 }
}
}
