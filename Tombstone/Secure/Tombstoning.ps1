<#
    Tombstone Script for cleaning up and managing old machines. All reference files
    located at $FolderLocation and sub-folders. This script has the
    functionality of cleaning up newly enabled machines in the Tombstone OU and trying to move them to
    their original OUs, and moving/disabling/deleting machines that meet the age criteria in
    the UserSettings.xml file. All simplified logging CSVs are emailed out to the recipients each day
    if the files exist. Computer disabling is delayed by 1 script run for SCCM device management and
    is done via the previous day's tombstone email CSV.

	written by: Walter Sowers
#>

#requires -modules ActiveDirectory

#region VariableSetup

# set variable for shared folder for files and import settings
$FolderLocation = %RootFolder #base folder for all of the files
$UserSettings = Import-Clixml ('{0}\UserSettings.xml' -f $FolderLocation)
$ExcludedOUs = Get-Content ('{0}\ExcludeOUs.txt' -f $FolderLocation)
$DailyTombstonedFile = '{0}\DailyTombstone.csv' -f $FolderLocation
$DailyDeletedFile = '{0}\DailyDeleted.csv' -f $FolderLocation
$DailyCleanupFile = '{0}\DailyCleanup.csv' -f $FolderLocation
$LoggingFile = '{0}\Tombstone.csv' -f $FolderLocation
$BLExport = '{0}\Secure\Tombstone_BLKeys.csv' -f $FolderLocation
$DisableComps = Import-Csv $DailyTombstonedFile -ErrorAction SilentlyContinue
$KeyFile = Import-Csv $BLExport
[System.Collections.ArrayList]$global:LoggingCSV = Import-Csv $LoggingFile
Remove-Item -Path ('{0}\*' -f $FolderLocation) -Include 'Daily*' -Force -ErrorAction SilentlyContinue

# set dates for the script
$Today = Get-Date
$SimpleDate = Get-Date -Format 'MM/dd/yyyy'
$TombstoneDate = $Today.Adddays(-$UserSettings.TombstoneAge)
$DeleteDate = $Today.AddDays(-$UserSettings.DeleteAge)
$BLFileDate = $Today.AddDays(-365)

# static OU assignments
$Domain = %domainName #name of your domain
$global:PDC = Get-ADDomainController -Discover -Service PrimaryDC -DomainName $Domain
$SearchBase = %basecomputerOU #OU where all of your workstations reside
$TombstoneOU = %tombstoneOU #OU where you place machines for tombstoning

# standard script variables
$Properties = @(
	'Name'
	'IPv4Address'
	'LastLogonDate'
	'Modified'
	'OperatingSystem'
	'OperatingSystemVersion'
	'SID'
	'Enabled'
	'DistinguishedName'
)

$DefaultMoveOU = %defaultComputerOU #default OU where newly-imaged/default machines are stored

# setup files for daily email
$EmailAttachments = @(
	$DailyTombstonedFile
	$DailyDeletedFile
	$DailyCleanupFile
)

#endregion VariableSetup

#region Functions

# add machines to logging CSV
FUNCTION Add-ToCSV {

	[cmdletbinding()]
	Param (
		$Add
	)

	$LoggingCSV.Add($Add)

}

# remove machines from logging csv
FUNCTION Remove-FromCSV {

	[cmdletbinding()]
	Param (
		$Remove
	)

	$Index = $LoggingCSV.Name.IndexOf($Remove.name)

    $LoggingCSV.RemoveAt($Index)
}

# clean up entries in the bitlocker file older than 1 year
function Cleanup-BLKeys {

    $BLFileResults = foreach ($Key in $KeyFile) {
        
        #$KeyDate = [datetime]::Parse($Key.Deleted)

        if ([datetime]::Parse($Key.Deleted) -gt $BLFileDate) {
            $Key
        }

    }

    $BLFileResults | Export-Csv $BLExport -NoTypeInformation -Force
}

# function for removing newly enabled machines from tombstone folder - # moved determined by usersettings.xml
function CleanUp-Tombstone {

	$NewlyActive = Get-ADComputer -Filter * -SearchBase $TombstoneOU -SearchScope Subtree -Server $PDC | where enabled -EQ $true

	if ($NewlyActive.Count -gt $UserSettings.MaxComps) {
		$ActiveComps = Get-Random $NewlyActive -Count $UserSettings.MaxComps
	} else {
		$ActiveComps = $NewlyActive
	}

	$ActiveResults = foreach ($Comp in $ActiveComps) {
    
		if ($Comp.Name -in $LoggingCSV.Name) {
			$Index = $LoggingCSV.Name.IndexOf($Comp.Name)

			$DestOU = $LoggingCSV[$Index].OriginalOU

			Remove-FromCSV -Remove $Comp
		} else {
			$DefaultMoveOU
		}

		Move-ADObject -Identity $Comp.DistinguishedName -TargetPath $DestOU -Server $PDC -Verbose

		$Obj = [pscustomobject]@{
			Name = $Comp.Name
			DestinationOU = $DestOU
		}
    
		$Obj
	}
    
	return $ActiveResults
}

# find all of the inactive computers in workstations OU based upon user defined settings - complete
FUNCTION Get-InactiveComputers {

	[cmdletbinding()]
	Param (
		[string]$SearchOU
	)

 	$InactiveParams = @{
		Filter = 'LastLogonDate -LT $TombstoneDate'
		SearchScope = 'onelevel'
		SearchBase = $SearchOU
		resultSetSize = $null
		Properties = $Properties
		Server = $PDC
	}
	
	$InactiveComputersList = Get-ADComputer @InactiveParams | where LastLogonDate -LT $TombstoneDate

	return $InactiveComputersList
}

# add the MaxComps machines to the tombstone OU and disable/leave according to user settings
Function Add-Tombstoned {

	[cmdletbinding()]
	Param (
		$Machine
	)

	Move-ADObject -Identity $Machine.DistinguishedName -TargetPath $TombstoneOU -Verbose
}

# find machines to delete from tombstone
FUNCTION Get-TombstoneToDelete {

	[cmdletbinding()]

	$DeleteParams = @{
		Filter = '*'
		SearchScope = 'subtree'
		SearchBase = $TombstoneOU
		resultSetSize = $null
		Properties = $Properties
	}
	
	$DeleteComputersList = Get-ADComputer @DeleteParams | where LastLogonDate -LT $DeleteDate

	return $DeleteComputersList
}

# delete machines past the tombstone age
FUNCTION Delete-Tombstoned {

	[cmdletbinding()]
	Param (
		$Machine
	)
    
	$Computer = Get-ADComputer $Machine -Properties ($Properties + 'ms-Mcs-AdmPwd')
	
	# Check if the machine has any leaf objects
	# If there are, then delete them first before trying to delete the computer

	$SubParams = @{
		LDAPFilter = "(objectClass=*)"
		SearchBase = $Computer.DistinguishedName
		SearchScope = "OneLevel"
	}

	$subObj = @(Get-ADObject @SubParams)
    
	if ($subObj.count -gt 0) {

		Remove-Variable KeyObj -ErrorAction SilentlyContinue

		$BLParams = @{
			Filter = "objectclass -eq 'msFVE-RecoveryInformation'"
			SearchBase = $Computer.DistinguishedName
			Properties = 'msFVE-RecoveryPassword'
		}

		$Bitlocker_Object = @(Get-ADObject @BLParams)
        
		$KeyObj = foreach ($Key in $Bitlocker_Object) {
                
			$Obj = [pscustomobject]@{
				Computer = $Computer.Name
				ID = $Key.DistinguishedName.Split("{}".ToCharArray())[1]
				Password = $Key.'msFVE-RecoveryPassword'
				Deleted = $SimpleDate
			}
			$Obj
		}

		ForEach ($DN in $subObj) {

			Remove-ADObject -Confirm:$false -Identity:$DN.DistinguishedName -Verbose 
		}
	}
	
	Remove-ADObject -Confirm:$false -Identity:$Computer.DistinguishedName -Verbose

	Return $Computer, $KeyObj
}

# take keys from deleted machines and append to csv
FUNCTION Save-BitLockerKeys {

	[cmdletbinding()]
	Param (
		$Keys
	)
    
	$Keys | Export-Csv $BLExport -NoTypeInformation -Append
}

# set email parameters and send email
FUNCTION Send-TombstoneEmail {

	# define email variables
    if ($CleanupResults.count -gt 0) {
        $CleanupCount = $CleanupResults.count
    } else {
        $CleanupCount = 0
    }
    
    if ($TombstoneComps.count -gt 0) {
        $TombstoneCount = $TombstoneComps.count
    } else {
        $TombstoneCount = 0
    }
    
    if ($CompFinal.count -gt 0) {
        $DeleteCount = $CompFinal.count
    } else {
        $DeleteCount = 0
    }

	$fromaddress = %fromAddress #address the email appears from. ex: "Team Name <distroList@domain.com>"
	$Subject = 'AD Workstation Purge Results'
	$Body = '<h2>See attachments for computers moved and deleted</h2><br><br>'
	$Body += 'Tombstone Cleaned up: {0}<br>' -f $CleanupCount
	$Body += 'Moved to Tombstone: {0}<br>' -f $TombstoneCount
	$Body += 'Deleted from Tombstone:{0}<br><br><br><br>' -f $DeleteCount
	#$Body += '*** Currently logging and testing ***'
	$smtpserver = %smtpServer #smtp server for your environment
 
	# populate and send mail
 	$message = new-object System.Net.Mail.MailMessage
	$message.From = $fromaddress
	foreach ($Address in $UserSettings.EmailRecipients) {
		$message.To.Add($Address)
	}
	$message.IsBodyHtml = $True
	$message.Subject = $Subject
    foreach ($File in $EmailAttachments) {
        if (Test-Path -LiteralPath $File) {
            $Attachment = new-object Net.Mail.Attachment($File)
            $message.Attachments.Add($Attachment)
        }
    }
	$message.body = $body
	$smtp = new-object Net.Mail.SmtpClient($smtpserver)
	$smtp.Send($message)
}

#endregion Functions

#region Tombstoned

# enabled or disabled in usersettings xml - reallydisable
if ($UserSettings.ReallyDisable -and $DisableComps.Count -gt 0) {
    foreach ($Comp in $DisableComps) {
		Set-ADComputer -Identity $Comp.Computer -Enabled $false -Verbose -Server $PDC
    }
}

Start-Sleep -Seconds 30

# clean computers out of tombstone if re-enabled and move back to original OU
# enabled or disabled from usersettings xml - cleanup
if ($UserSettings.CleanUp) {
	$CleanupResults = CleanUp-Tombstone

    # export CleanUP csv
	$CleanupResults | Export-Csv $DailyCleanupFile -Force -NoTypeInformation
}

# create a regular expression string combining the OUs with the 'OR' pipe symbol and wrap that
# inside a non-capturing group. The $ means the match should end in any of the 'OR'-ed ou DNs
$reExcludeOUs = '(?:{0})$' -f ($ExcludedOUs -join '|')

# Build a list of OUs and remove the exclusions
$OUParams = @{
	SearchBase = $SearchBase
	SearchScope = 'Subtree'
	Filter = '*'
}

$AllOUs = Get-ADOrganizationalUnit @OUParams

$OUsToBeSearched = $AllOUs | where distinguishedName -notmatch $reExcludeOUs | select DistinguishedName

# Iterate through the list of OUs and gather inactive computers within the OUs
$InactiveComputerCollection = foreach ($OU in $OUsToBeSearched) {
	Get-InactiveComputers -SearchOU $OU.DistinguishedName
}

# pull random computers from inactive computers list if greater than usersettings.xml
if ($InactiveComputerCollection.Count -gt $UserSettings.MaxComps) {
	$TombstoneComps = Get-Random $InactiveComputerCollection -Count $UserSettings.MaxComps
} else {
	$TombstoneComps = $InactiveComputerCollection
}

if ($TombstoneComps.count -gt 0) {
	# create simplified array for daily tombstone email attachment
	$EmailTombstone = foreach ($Comp in $TombstoneComps) {

		$FromOU = $Comp.DistinguishedName -split ',',2

		$Cmp = [pscustomobject]@{
			Computer = $Comp.Name
			Tombstoned = $SimpleDate
			OriginalOU = $FromOU[1]
			OS = $Comp.OperatingSystem
			OS_Version = $Comp.OperatingSystemVersion
		}

		$Cmp
	}

	# export tombstone CSV for attachment
	$EmailTombstone | Export-Csv $DailyTombstonedFile -Force -NoTypeInformation

	# tombstone machines past $tombstoneage and create array to add to loggingCSV with original OU location
	foreach ($Computer in $TombstoneComps) {

		Add-Tombstoned -Machine $Computer

		$OriginalOU = $Computer.DistinguishedName -split ',',2

		$Obj = [pscustomobject]@{
			Name = $Computer.Name
			DistinguishedName = $Computer.DistinguishedName
			Enabled = (Get-ADComputer $Computer -Properties enabled | select enabled).enabled
			OriginalOU = $OriginalOU[1]
			IPv4Address = $Computer.IPv4Address
			LastLogonDate = $Computer.LastLogonDate
			Modified = $Computer.Modified
			ObjectGUID = $Computer.ObjectGUID
			OperatingSystem = $Computer.OperatingSystem
			OperatingSystemVersion = $Computer.OperatingSystemVersion
			SID = $Computer.SID
		}
	
		$Obj

		Add-ToCSV -Add $Obj
	}
}

#endregion Tombstoned

#region Deleted

# find machines to delete from tombstone past usersettings xml - DeleteDage
$TombstoneCollection = Get-TombstoneToDelete 

if ($TombstoneCollection.Count -gt $UserSettings.MaxComps) {
	$TombstoneDeleteCollection = $TombstoneCollection | Get-Random -Count $UserSettings.MaxComps
} else {
	$TombstoneDeleteCollection = $TombstoneCollection
}

# delete and log deleted machines, export known BL keys to CSV archive
# enabled or disabled in usersettings xml - reallydelete
if ($TombstoneDeleteCollection.count -gt 0) {
	if ($UserSettings.ReallyDelete) {

		[System.Collections.ArrayList]$CompInfo = @()
		[System.Collections.ArrayList]$BLInfo = @()

		foreach ($DeleteComp in $TombstoneDeleteCollection) {
			$Return = Delete-Tombstoned -Machine $DeleteComp.Name

			if ($DeleteComp.Name -in $LoggingCSV.Name) {
				Remove-FromCSV -Remove $DeleteComp
			}

			$CompInfo.Add($Return[0])
			$BLInfo.Add($Return[1])
		}

		$BLFinal = foreach ($Key in $BLInfo) {
			if ($null -ne $Key) {
				$Key
			}
		}
		$CompFinal = foreach ($Comp in $CompInfo) {
			if ($null -ne $Comp) {
				$Comp
			}
		}
	}

	# create simplified array for daily deleted csv attachment
	$EmailDelete = foreach ($Comp in $CompFinal) {

        if ($null -ne $Comp.'ms-Mcs-AdmPwd') {
            $LAPS = $Comp.'ms-Mcs-AdmPwd'
        } else {
            $LAPS = $null
        }

		$Cmp = [pscustomobject]@{
			Computer = $Comp.Name
			Deleted = $SimpleDate
			OS = $Comp.OperatingSystem
			OS_Version = $Comp.OperatingSystemVersion
            LAPS = $LAPS
		}

		$Cmp
	}

	# export daily deleted csv
	$EmailDelete | Export-Csv $DailyDeletedFile -Force -NoTypeInformation

    # export saved bitlocker keys to file
    if ($BLFinal.count -gt 0) {
	    Save-BitLockerKeys -Keys $BLFinal
    }
}
#endregion Deleted

#region Finalization

# export all logging info to csv
$LoggingCSV | Export-Csv $LoggingFile -Force -NoTypeInformation

# send results in email to recipients defined in usersettings.xml
Send-TombstoneEmail

#Cleanup-BLKeys

#endregion Finalization