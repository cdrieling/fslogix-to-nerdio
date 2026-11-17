#requires -Version 5.1
<#
.SYNOPSIS
    Reads the FSLogix configuration of a session host and writes a single-file HTML report
    that says, setting by setting, where it goes in Nerdio Manager for Enterprise (NME).

.DESCRIPTION
    Read-only. The script never writes to the registry, never touches a profile container
    and never contacts the network unless you ask it to (-TestPaths, -IncludeGpResult).

    It collects:
      * HKLM\SOFTWARE\FSLogix\{Profiles,ODFC,Apps,Logging} and the matching Policies keys
      * the FSLogix agent version and the state of its services
      * the FSLogix Profile/ODFC Include and Exclude local groups
      * redirections.xml, if RedirXMLSourceFolder points at one
      * the App Masking rule files, if any
      * whether the machine is domain joined, Entra ID joined, or both

    and renders one self-contained HTML file: a setting-by-setting map onto the NME fields,
    paste-ready blocks for NME's "Advanced" registry editor, and the findings that decide
    whether the rebuilt configuration will actually hold (Group Policy above all).

.PARAMETER OutputPath
    Where to write the HTML. Default: .\fslogix-nerdio-<computer>-<yyyyMMdd-HHmm>.html

.PARAMETER SaveJson
    Also write the raw capture as JSON. Useful to render the report somewhere else, or to
    diff two hosts.

.PARAMETER FromJson
    Render the report from a capture written earlier by -SaveJson instead of reading the
    local registry. Works on any operating system; nothing is collected.

.PARAMETER CatalogPath
    A JSON file overriding the built-in annotation catalogue. See docs/catalog.md.

.PARAMETER TestPaths
    Probe the profile and Office container paths with Test-Path. Off by default, because a
    dead UNC path can block for a long time.

.PARAMETER IncludeGpResult
    Run `gpresult /scope computer /r` and include the list of applied GPOs in the report.
    Off by default; it needs a few seconds and a reachable domain controller.

.PARAMETER NoLaunch
    Do not open the report when it is done.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Export-FSLogixConfig.ps1

.EXAMPLE
    .\Export-FSLogixConfig.ps1 -SaveJson .\host.json -TestPaths

.EXAMPLE
    pwsh ./Export-FSLogixConfig.ps1 -FromJson ./samples/sample-capture.json -OutputPath ./report.html

.NOTES
    Copyright (c) 2026 Christian T. Drieling. Licensed under the Apache License 2.0.
    Not affiliated with, or endorsed by, Nerdio or Microsoft.
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [string] $SaveJson,
    [string] $FromJson,
    [string] $CatalogPath,
    [switch] $TestPaths,
    [switch] $IncludeGpResult,
    [switch] $NoLaunch
)

$ErrorActionPreference = 'Stop'
$script:SchemaVersion  = 'fslogix-to-nerdio/1'
$script:ToolVersion    = '1.1.2'

# What each collector managed to do. The point of this list is that "not found" and "not
# allowed to look" must never render the same way -- especially when the script runs as an
# ordinary user, which is the normal case on a session host.
$script:Collectors = @()

# --------------------------------------------------------------------------------------
# Areas. One per FSLogix registry key that NME exposes as its own editor.
#
#   DefaultClass  what NME does with a value here that the catalogue says nothing about:
#                 'registry' -> FSLogix Registry Options (All settings / Advanced)
#                 'editor'   -> the named sub-editor of the FSLogix profile
#   NmeTarget     the NME control that holds this area
# --------------------------------------------------------------------------------------
$script:Areas = [ordered]@{
    'Profiles' = [ordered]@{
        Title        = 'Profile Container'
        ProductKey   = 'HKLM:\SOFTWARE\FSLogix\Profiles'
        PolicyKey    = 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles'
        DefaultClass = 'registry'
        NmeTarget    = 'FSLogix Registry Options'
        Blurb        = 'The profile container itself. In NME everything in this table that is not a named field is entered under FSLogix Registry Options.'
    }
    'ODFC' = [ordered]@{
        Title        = 'Office Container (ODFC)'
        ProductKey   = 'HKLM:\SOFTWARE\FSLogix\ODFC'
        PolicyKey    = 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC'
        DefaultClass = 'registry'
        NmeTarget    = 'FSLogix Office Container Registry Options'
        Blurb        = 'The Office container. NME only shows this section once "Configure Office Container to redirect Microsoft Office user data" is toggled on.'
    }
    'Apps' = [ordered]@{
        Title        = 'App Services'
        ProductKey   = 'HKLM:\SOFTWARE\FSLogix\Apps'
        PolicyKey    = 'HKLM:\SOFTWARE\Policies\FSLogix\Apps'
        DefaultClass = 'editor'
        NmeTarget    = 'Manage App Service settings'
        Blurb        = 'The FSLogix application services. In NME these sit behind the "Manage App Service settings" checkbox of the FSLogix profile.'
    }
    'Logging' = [ordered]@{
        Title        = 'Logging'
        ProductKey   = 'HKLM:\SOFTWARE\FSLogix\Logging'
        PolicyKey    = 'HKLM:\SOFTWARE\Policies\FSLogix\Logging'
        DefaultClass = 'editor'
        NmeTarget    = 'Manage Log settings'
        Blurb        = 'Log destinations and levels. In NME these sit behind the "Manage Log settings" checkbox of the FSLogix profile.'
    }
}

# Documentation anchors, all from the Nerdio help centre.
$script:Doc = @{
    Settings  = 'https://nmehelp.getnerdio.com/hc/en-us/articles/25499417371661-FSLogix-settings-and-configuration'
    PerPool   = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26124330262925-FSLogix-per-host-pool-customization'
    Overview  = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26126637566477-FSLogix-and-User-Profile-Management'
    EntraId   = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26124360018445-Use-Azure-Files-with-Entra-ID-joined-method-for-AVD'
    Identity  = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26124371716109-FSLogix-Identity-Roaming-for-Credentials-and-Tokens'
    LocalAdm  = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26124309756429-Troubleshoot-Unable-to-Sign-In-to-Session-Host-VMs-as-Local-Administrator'
    MountErr  = 'https://nmehelp.getnerdio.com/hc/en-us/articles/26124330262925-FSLogix-per-host-pool-customization'
    MsRef     = 'https://learn.microsoft.com/fslogix/reference-configuration-settings'
}

# --------------------------------------------------------------------------------------
# The annotation catalogue.
#
# Entries are keyed "<AREA>|<VALUENAME>", upper case. Every entry is an annotation on a
# value that was actually found in the registry -- an entry that matches nothing is inert,
# so an incomplete or slightly wrong catalogue cannot lose a setting. Values with no entry
# fall back to their area's DefaultClass.
#
#   Class  'field'     NME has a dedicated control for this -> do not paste it as registry
#          'registry'  FSLogix Registry Options
#          'editor'    the area's own NME editor
#          'unmanaged' NME does not carry this
#   Field  name of the NME control, for Class 'field'
#   Note   one sentence, shown in the report
#   Doc    link shown on the row
#   Enum   value -> meaning
# --------------------------------------------------------------------------------------
function Get-BuiltInCatalog {
    $c = @{}

    function Add-Entry($key, $hash) { $c[$key.ToUpperInvariant()] = $hash }

    # --- Profile container -------------------------------------------------------------
    Add-Entry 'Profiles|Enabled' @{
        Class = 'field'; Field = 'Enable FSLogix profiles'
        Note  = 'Per host pool: Settings > FSLogix > Enable FSLogix profiles. NME installs the agent on new or re-imaged hosts when this is on.'
        Doc   = $script:Doc.PerPool
        Enum  = @{ '0' = 'disabled'; '1' = 'enabled' }
    }
    Add-Entry 'Profiles|VHDLocations' @{
        Class = 'field'; Field = 'FSLogix Profiles path (VHDLocation)'
        Note  = 'Pick the Azure Files share from the drop-down or type a UNC path. Up to four, and the order is kept.'
        Doc   = $script:Doc.Settings
    }
    Add-Entry 'Profiles|CCDLocations' @{
        Class = 'field'; Field = 'Use Cloud Cache'
        Note  = 'Cloud Cache is a checkbox in NME; its locations replace the plain profile path. Premium SSD plus ephemeral OS disks are the documented recommendation.'
        Doc   = $script:Doc.Settings
    }
    Add-Entry 'Profiles|RedirXMLSourceFolder' @{
        Class = 'field'; Field = 'Redirections'
        Note  = 'NME keeps one redirections.xml with the profile and distributes it; the folder path here is replaced by that mechanism. The current file is reproduced further down.'
        Doc   = $script:Doc.Settings
    }
    Add-Entry 'Profiles|ProfileType' @{
        Class = 'registry'
        Note  = 'Concurrent access mode. Anything but 0 needs a deliberate decision -- check it against the host pool type before copying it.'
        Enum  = @{ '0' = 'normal, single session'; '1' = 'read-write container only'; '2' = 'read-only container only'; '3' = 'read-write and read-only concurrently' }
        Doc   = $script:Doc.MsRef
    }
    Add-Entry 'Profiles|VolumeType' @{ Class = 'registry'; Note = 'VHDX is the current default; VHD only for legacy shares.' ; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|SizeInMBs' @{ Class = 'registry'; Note = 'Maximum container size. FSLogix default is 30000 (about 30 GB).'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|IsDynamic' @{ Class = 'registry'; Note = 'Dynamically expanding container. Off means the full size is allocated on the share immediately.'; Enum = @{ '0' = 'fixed size'; '1' = 'dynamic' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|FlipFlopProfileDirectoryName' @{ Class = 'registry'; Note = 'Folder naming on the share: username_SID instead of SID_username. Changing it orphans every existing container -- keep whatever the share already uses.'; Enum = @{ '0' = 'SID_username'; '1' = 'username_SID' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|SIDDirNamePattern' @{ Class = 'registry'; Note = 'Custom folder naming. Must match SIDDirNameMatch and the layout that already exists on the share.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|SIDDirNameMatch'   @{ Class = 'registry'; Note = 'Custom folder naming, the matching half of SIDDirNamePattern.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|DeleteLocalProfileWhenVHDShouldApply' @{
        Class = 'registry'
        Note  = 'Deletes a local profile when a container should have applied. Destructive on the host, and the usual cure for "temp profile" symptoms on pooled hosts.'
        Enum  = @{ '0' = 'keep local profile'; '1' = 'delete local profile' }
        Doc   = $script:Doc.MsRef
    }
    Add-Entry 'Profiles|PreventLoginWithFailure'      @{ Class = 'registry'; Note = 'Blocks sign-in when the container fails. Together with the exclude groups this decides whether an admin can still get on the host.'; Enum = @{ '0' = 'allow sign-in'; '1' = 'block sign-in' }; Doc = $script:Doc.LocalAdm }
    Add-Entry 'Profiles|PreventLoginWithTempProfile'  @{ Class = 'registry'; Note = 'Blocks sign-in with a temporary profile.'; Enum = @{ '0' = 'allow temp profile'; '1' = 'block temp profile' }; Doc = $script:Doc.LocalAdm }
    Add-Entry 'Profiles|AccessNetworkAsComputerObject' @{
        Class = 'registry'
        Note  = 'Required for Azure Files with Entra ID Kerberos. NME also has a checkbox, "Configure session hosts registry for Entra ID joined storage" -- use the checkbox and verify this value afterwards instead of setting both by hand.'
        Enum  = @{ '0' = 'user context'; '1' = 'computer object' }
        Doc   = $script:Doc.EntraId
    }
    Add-Entry 'Profiles|RoamIdentity' @{ Class = 'registry'; Note = 'Identity roaming for credentials and tokens. The help centre documents it as an Advanced line: "RoamIdentity"=dword:00000001.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.Identity }
    Add-Entry 'Profiles|RoamSearch'   @{ Class = 'registry'; Note = 'Legacy per-user search roaming. Removed from current FSLogix releases -- check whether it still applies before carrying it over.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|SetTempToLocalPath' @{ Class = 'registry'; Note = 'Redirects TEMP/TMP and the INetCache out of the container.'; Enum = @{ '0' = 'no redirection'; '1' = 'TEMP and TMP'; '2' = 'INetCache'; '3' = 'TEMP, TMP and INetCache' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|VHDCompactDisk' @{ Class = 'registry'; Note = 'Compacts the container on sign-out. NME also ships a scripted action, "FSLogix Shrink VHD/VHDX Containers", for doing this on a schedule.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|CacheDirectory' @{ Class = 'registry'; Note = 'Cloud Cache local cache path. Only meaningful with Cloud Cache on, and it wants fast local disk.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|ClearCacheOnLogoff' @{ Class = 'registry'; Note = 'Cloud Cache: discard the local cache at sign-out.'; Enum = @{ '0' = 'keep cache'; '1' = 'clear cache' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|HealthyProvidersRequiredForRegister'   @{ Class = 'registry'; Note = 'Cloud Cache: how many providers must be healthy to sign in.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|HealthyProvidersRequiredForUnregister' @{ Class = 'registry'; Note = 'Cloud Cache: how many providers must be healthy to sign out.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|LockedRetryCount'        @{ Class = 'registry'; Note = 'Retries when the container is locked by another host.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|LockedRetryInterval'     @{ Class = 'registry'; Note = 'Seconds between those retries.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|ReAttachIntervalSeconds' @{ Class = 'registry'; Note = 'Seconds between re-attach attempts after a disconnect.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|ReAttachRetryCount'      @{ Class = 'registry'; Note = 'Number of re-attach attempts.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|KeepLocalDir'            @{ Class = 'registry'; Note = 'Keeps the local profile directory after the container is attached.'; Enum = @{ '0' = 'remove'; '1' = 'keep' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|NoProfileContainingFolder' @{ Class = 'registry'; Note = 'Containers sit directly in the share root instead of a per-user folder.'; Enum = @{ '0' = 'per-user folder'; '1' = 'share root' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|OutlookCachedMode'       @{ Class = 'registry'; Note = 'Forces Outlook cached mode for container users.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|RemoveOrphanedOSTFilesOnLogoff' @{ Class = 'registry'; Note = 'Housekeeping for OST files left behind in the container.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|ConcurrentUserSessions'  @{ Class = 'registry'; Note = 'Allows the same user in more than one session against one container.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|ProfileDirSDDL'          @{ Class = 'registry'; Note = 'SDDL applied to the profile directory. Carry it over verbatim or not at all.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|SIDDirSDDL'              @{ Class = 'registry'; Note = 'SDDL applied to the per-SID directory.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|VHDNameMatch'            @{ Class = 'registry'; Note = 'Container file naming, matching half.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|VHDNamePattern'          @{ Class = 'registry'; Note = 'Container file naming, pattern half.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|VHDXSectorSize'          @{ Class = 'registry'; Note = 'Sector size of newly created containers.'; Doc = $script:Doc.MsRef }
    Add-Entry 'Profiles|DiffDiskParentFolderPath' @{ Class = 'registry'; Note = 'Parent folder for difference disks.'; Doc = $script:Doc.MsRef }

    # --- Office container ---------------------------------------------------------------
    Add-Entry 'ODFC|Enabled' @{
        Class = 'field'; Field = 'Configure Office Container to redirect Microsoft Office user data'
        Note  = 'The toggle that reveals the Office container section in NME.'
        Enum  = @{ '0' = 'disabled'; '1' = 'enabled' }
        Doc   = $script:Doc.Settings
    }
    Add-Entry 'ODFC|VHDLocations' @{ Class = 'field'; Field = 'FSLogix Office Container path (VHDLocation)'; Note = 'Can and often should be a different share than the profile container.'; Doc = $script:Doc.Settings }
    Add-Entry 'ODFC|CCDLocations' @{ Class = 'field'; Field = 'Use Cloud Cache'; Note = 'Cloud Cache locations for the Office container.'; Doc = $script:Doc.Settings }
    foreach ($inc in 'IncludeOfficeActivation','IncludeOneDrive','IncludeOneNote','IncludeOneNote_UWP','IncludeOutlook','IncludeOutlookPersonalization','IncludeSharepoint','IncludeSkype','IncludeTeams') {
        Add-Entry "ODFC|$inc" @{ Class = 'registry'; Note = 'Which Office data lands in the Office container.'; Enum = @{ '0' = 'excluded'; '1' = 'included' }; Doc = $script:Doc.MsRef }
    }
    Add-Entry 'ODFC|MirrorLocalOSTToVHD'  @{ Class = 'registry'; Note = 'How an existing local OST is treated when the container attaches.'; Doc = $script:Doc.MsRef }
    Add-Entry 'ODFC|NumSessionVHDsToKeep' @{ Class = 'registry'; Note = 'How many per-session Office containers are kept.'; Doc = $script:Doc.MsRef }
    Add-Entry 'ODFC|SizeInMBs'  @{ Class = 'registry'; Note = 'Maximum Office container size.'; Doc = $script:Doc.MsRef }
    Add-Entry 'ODFC|VolumeType' @{ Class = 'registry'; Note = 'VHDX or VHD for the Office container.'; Doc = $script:Doc.MsRef }
    Add-Entry 'ODFC|IsDynamic'  @{ Class = 'registry'; Note = 'Dynamically expanding Office container.'; Enum = @{ '0' = 'fixed size'; '1' = 'dynamic' }; Doc = $script:Doc.MsRef }

    # --- App services and logging -------------------------------------------------------
    Add-Entry 'Apps|CleanupInvalidSessions' @{ Class = 'editor'; Note = 'Cleans up sessions left behind by a crash.'; Enum = @{ '0' = 'off'; '1' = 'on' }; Doc = $script:Doc.Settings }
    Add-Entry 'Apps|RoamSearch'             @{ Class = 'editor'; Note = 'Legacy search roaming on the app service side.'; Doc = $script:Doc.MsRef }
    # Written by the FSLogix installer, not by anyone configuring it. Carrying these over
    # would put one host's install state into another environment's profile.
    Add-Entry 'Apps|InstallPath'    @{ Class = 'unmanaged'; Note = 'Where the FSLogix agent is installed, written by its installer. Nerdio Manager installs the agent itself -- nothing to carry over.'; Doc = $script:Doc.Settings }
    Add-Entry 'Apps|InstallVersion' @{ Class = 'unmanaged'; Note = 'The agent version this host happens to have, written by its installer. In NME you choose it in the profile''s Version drop-down instead of copying it.'; Doc = $script:Doc.Settings }
    Add-Entry 'Apps|InstallDate'    @{ Class = 'unmanaged'; Note = 'When the agent was installed here. Install state, not configuration.'; Doc = $script:Doc.Settings }
    Add-Entry 'Logging|LogDir'              @{ Class = 'editor'; Note = 'Log destination. A UNC path here means every host writes to one share -- check it still exists in the target environment.'; Doc = $script:Doc.Settings }
    Add-Entry 'Logging|LogFileKeepingPeriod' @{ Class = 'editor'; Note = 'Days of logs kept on the host.'; Doc = $script:Doc.Settings }
    Add-Entry 'Logging|LoggingEnabled'      @{ Class = 'editor'; Note = 'Global logging switch.'; Doc = $script:Doc.Settings }

    return $c
}

# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------
function Get-Prop {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $Default
}

function ConvertTo-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Protect-Html {
    param([string] $Text)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"', '&quot;'
    return $t
}

function Write-JsonValue {
    # Windows PowerShell 5.1's ConvertTo-Json is the one component here with a reputation for
    # going away and not coming back on perfectly ordinary objects. The capture's shape is
    # fully ours -- strings, numbers, booleans, nulls, arrays and property bags -- so it is
    # cheaper to write the twenty lines than to debug someone else's serialiser on a host we
    # do not have. This also makes the output identical on 5.1 and 7.x.
    param([System.Text.StringBuilder] $Sb, $Value, [int] $Indent)

    $pad  = ' ' * ($Indent * 2)
    $pad2 = ' ' * (($Indent + 1) * 2)

    if ($null -eq $Value) { [void] $Sb.Append('null'); return }

    if ($Value -is [bool])     { [void] $Sb.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [string])   { [void] $Sb.Append((ConvertTo-JsonString $Value)); return }
    if ($Value -is [datetime]) { [void] $Sb.Append((ConvertTo-JsonString ($Value.ToString('yyyy-MM-ddTHH:mm:sszzz')))); return }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        [void] $Sb.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
        return
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $names = @($Value.Keys)
        if ($names.Count -eq 0) { [void] $Sb.Append('{}'); return }
        [void] $Sb.Append("{`n")
        for ($i = 0; $i -lt $names.Count; $i++) {
            [void] $Sb.Append($pad2).Append((ConvertTo-JsonString ([string] $names[$i]))).Append(': ')
            Write-JsonValue -Sb $Sb -Value $Value[$names[$i]] -Indent ($Indent + 1)
            if ($i -lt $names.Count - 1) { [void] $Sb.Append(',') }
            [void] $Sb.Append("`n")
        }
        [void] $Sb.Append($pad).Append('}')
        return
    }

    if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { [void] $Sb.Append('[]'); return }
        [void] $Sb.Append("[`n")
        for ($i = 0; $i -lt $items.Count; $i++) {
            [void] $Sb.Append($pad2)
            Write-JsonValue -Sb $Sb -Value $items[$i] -Indent ($Indent + 1)
            if ($i -lt $items.Count - 1) { [void] $Sb.Append(',') }
            [void] $Sb.Append("`n")
        }
        [void] $Sb.Append($pad).Append(']')
        return
    }

    $props = @($Value.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -or $_.MemberType -eq 'Property' })
    if ($props.Count -eq 0) { [void] $Sb.Append((ConvertTo-JsonString ([string] $Value))); return }
    [void] $Sb.Append("{`n")
    for ($i = 0; $i -lt $props.Count; $i++) {
        [void] $Sb.Append($pad2).Append((ConvertTo-JsonString $props[$i].Name)).Append(': ')
        $pv = $null
        try { $pv = $props[$i].Value } catch { $pv = $null }
        Write-JsonValue -Sb $Sb -Value $pv -Indent ($Indent + 1)
        if ($i -lt $props.Count - 1) { [void] $Sb.Append(',') }
        [void] $Sb.Append("`n")
    }
    [void] $Sb.Append($pad).Append('}')
}

function ConvertTo-JsonString {
    param([string] $Text)
    $sb = New-Object System.Text.StringBuilder
    [void] $sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        switch ($ch) {
            '"'      { [void] $sb.Append('\"') }
            '\'      { [void] $sb.Append('\\') }
            "`b"     { [void] $sb.Append('\b') }
            "`f"     { [void] $sb.Append('\f') }
            "`n"     { [void] $sb.Append('\n') }
            "`r"     { [void] $sb.Append('\r') }
            "`t"     { [void] $sb.Append('\t') }
            default  {
                if ([int] $ch -lt 32) { [void] $sb.Append('\u').Append(('{0:x4}' -f [int] $ch)) }
                else                  { [void] $sb.Append($ch) }
            }
        }
    }
    [void] $sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-CaptureJson {
    param($Value)
    $sb = New-Object System.Text.StringBuilder
    Write-JsonValue -Sb $sb -Value $Value -Indent 0
    return $sb.ToString()
}

function Add-CollectorStatus {
    # Status: ok | empty | absent | denied | error | skipped
    param([string] $Name, [string] $Status, [string] $Detail, [string] $Source)
    $script:Collectors += [pscustomobject] [ordered]@{
        name = $Name; status = $Status; detail = $Detail; source = $Source
    }
}

function Get-ErrorKind {
    param($ErrorRecord)
    $msg = [string] $ErrorRecord.Exception.Message
    if ($ErrorRecord.Exception -is [System.UnauthorizedAccessException]) { return 'denied' }
    if ($ErrorRecord.Exception -is [System.Security.SecurityException])   { return 'denied' }
    if ($msg -match 'Requested registry access is not allowed|Access to the path|Zugriff verweigert|is denied') { return 'denied' }
    return 'error'
}

function Get-TestablePath {
    # FSLogix expands %username%, %sid% and the rest when a user signs in. Nothing expands
    # them here, so probing the literal string probes a folder that cannot exist. Cut the
    # path before the first variable and probe what is left -- which is the share, and the
    # only part of this that a report can sensibly say anything about.
    param([string] $Path)
    $p = [string] $Path
    $i = $p.IndexOf('%')
    if ($i -ge 0) { $p = $p.Substring(0, $i) }
    return $p.TrimEnd('\')
}

function Test-SmbHostReachable {
    # A dead or filtered SMB host makes Test-Path sit there for minutes. Ask TCP 445 first,
    # with a timeout we choose, and only then touch the file system.
    param([string] $HostName, [int] $TimeoutMs = 3000)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($HostName, 445, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Test-PathBounded {
    # Test-Path with a wall clock on it. A job costs about a second; an unreachable share
    # costs minutes, which is what made this switch look like a hang.
    param([string] $Path, [int] $TimeoutSeconds = 15)
    $job = $null
    try {
        $job = Start-Job -ScriptBlock { param($p) Test-Path -LiteralPath $p } -ArgumentList $Path
        if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
            return [pscustomobject] @{ reachable = [bool] (Receive-Job -Job $job); timedOut = $false }
        }
        return [pscustomobject] @{ reachable = $false; timedOut = $true }
    } catch {
        return [pscustomobject] @{ reachable = $false; timedOut = $false }
    } finally {
        if ($job) { try { Remove-Job -Job $job -Force } catch { } }
    }
}

function Test-IsElevated {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return [bool] $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $null }
}

function Test-IsWindows {
    if ($PSVersionTable.PSVersion.Major -le 5) { return $true }
    return [bool] (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

# --------------------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------------------
function Read-RegistryArea {
    param([string] $Path, [string] $Area, [string] $Scope)

    $shown  = ($Path -replace '^HKLM:', 'HKLM')
    $label  = ('Registry {0} ({1})' -f $shown, $Scope)
    $result = [ordered]@{ area = $Area; scope = $Scope; path = $shown; exists = $false; readable = $true; error = $null; values = @() }

    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        $result.readable = $false
        $result.error = $_.Exception.Message
        Add-CollectorStatus -Name $label -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source $shown
        return [pscustomobject] $result
    }
    if (-not $exists) {
        Add-CollectorStatus -Name $label -Status 'absent' -Detail 'key does not exist on this host' -Source $shown
        return [pscustomobject] $result
    }

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch {
        $result.exists = $true
        $result.readable = $false
        $result.error = $_.Exception.Message
        Add-CollectorStatus -Name $label -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source $shown
        return [pscustomobject] $result
    }
    $result.exists = $true
    $values = @()
    foreach ($name in ($key.GetValueNames() | Sort-Object)) {
        if ([string]::IsNullOrEmpty($name)) { continue }   # the (Default) value carries nothing here
        $kind = 'Unknown'
        try { $kind = [string] $key.GetValueKind($name) } catch { }
        $raw = $null
        try { $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } catch { }

        $display = ''
        if ($raw -is [byte[]])            { $display = (($raw | ForEach-Object { '{0:x2}' -f $_ }) -join ' ') }
        elseif ($raw -is [array])         { $display = ($raw -join "`n") }
        elseif ($kind -eq 'DWord' -or $kind -eq 'QWord') { $display = [string] $raw }
        else                              { $display = [string] $raw }

        $values += [pscustomobject] [ordered]@{
            name    = $name
            kind    = $kind
            data    = $(if ($raw -is [byte[]]) { $display } else { $raw })
            display = $display
        }
    }
    $result.values = $values
    $status = 'ok'
    if ($values.Count -eq 0) { $status = 'empty' }
    Add-CollectorStatus -Name $label -Status $status -Detail ('{0} value(s)' -f $values.Count) -Source $shown
    return [pscustomobject] $result
}

function Get-FSLogixVersion {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'FSLogix\Apps\frxsvc.exe'),
        (Join-Path $env:ProgramFiles 'FSLogix\Apps\frxccd.exe')
    )
    foreach ($c in $candidates) {
        try {
            if (Test-Path -LiteralPath $c -ErrorAction Stop) {
                $v = (Get-Item -LiteralPath $c -ErrorAction Stop).VersionInfo.FileVersion
                Add-CollectorStatus -Name 'FSLogix agent version' -Status 'ok' -Detail $v -Source $c
                return $v
            }
        } catch {
            Add-CollectorStatus -Name 'FSLogix agent version' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source $c
            return $null
        }
    }
    Add-CollectorStatus -Name 'FSLogix agent version' -Status 'absent' -Detail 'frxsvc.exe not found under Program Files' -Source (Join-Path $env:ProgramFiles 'FSLogix\Apps')
    return $null
}

function Get-JoinState {
    # Only the three answers are kept. dsregcmd's full output carries the tenant id, the
    # device id and certificate thumbprint and the signed-in user's address, none of which
    # the report shows -- and a capture travels: to a colleague, into a ticket, out of the
    # customer's environment. What is not collected cannot leak.
    $state = [ordered]@{ domainJoined = $null; entraJoined = $null; entraHybrid = $null }
    try {
        $out = & dsregcmd.exe /status 2>$null
        if ($out) {
            $text = ($out -join "`n")
            $state.domainJoined = [bool] ($text -match '(?m)^\s*DomainJoined\s*:\s*YES')
            $state.entraJoined  = [bool] ($text -match '(?m)^\s*AzureAdJoined\s*:\s*YES')
            $state.entraHybrid  = ($state.domainJoined -and $state.entraJoined)
            Add-CollectorStatus -Name 'Join state' -Status 'ok' -Detail 'dsregcmd /status' -Source 'dsregcmd.exe'
        } else {
            Add-CollectorStatus -Name 'Join state' -Status 'empty' -Detail 'dsregcmd produced no output' -Source 'dsregcmd.exe'
        }
    } catch {
        Add-CollectorStatus -Name 'Join state' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source 'dsregcmd.exe'
    }
    return [pscustomobject] $state
}

function Get-FSLogixGroups {
    $names = @(
        'FSLogix Profile Include List', 'FSLogix Profile Exclude List',
        'FSLogix ODFC Include List',    'FSLogix ODFC Exclude List'
    )
    $groups = @()
    foreach ($n in $names) {
        $entry = [ordered]@{ name = $n; exists = $false; members = @(); memberSids = @(); error = $null }
        try {
            $g = Get-LocalGroup -Name $n -ErrorAction Stop
            $entry.exists = $true
            $members = @()
            $sids = @()
            foreach ($m in (Get-LocalGroupMember -Group $g -ErrorAction Stop)) {
                $members += [string] $m.Name
                if ($m.SID) { $sids += [string] $m.SID.Value }
            }
            $entry.members = $members
            $entry.memberSids = $sids
        } catch {
            # Get-LocalGroupMember trips over orphaned or Entra-only SIDs; fall back to net.exe
            try {
                $raw = & net.exe localgroup "$n" 2>$null
                if ($LASTEXITCODE -eq 0 -and $raw) {
                    $entry.exists = $true
                    $members = @()
                    $collect = $false
                    foreach ($line in $raw) {
                        if ($line -match '^-{3,}') { $collect = $true; continue }
                        if (-not $collect) { continue }
                        if ($line -match '^The command completed') { continue }
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        $members += $line.Trim()
                    }
                    $entry.members = $members
                } else {
                    $entry.error = 'group not found'
                }
            } catch {
                $entry.error = $_.Exception.Message
            }
        }

        if ($entry.exists) {
            $st = 'ok'
            if (@($entry.members).Count -eq 0) { $st = 'empty' }
            Add-CollectorStatus -Name ('Group "{0}"' -f $n) -Status $st -Detail ('{0} member(s)' -f @($entry.members).Count) -Source 'local groups'
        } elseif ($entry.error -and $entry.error -ne 'group not found') {
            Add-CollectorStatus -Name ('Group "{0}"' -f $n) -Status 'denied' -Detail $entry.error -Source 'local groups'
        } else {
            Add-CollectorStatus -Name ('Group "{0}"' -f $n) -Status 'absent' -Detail 'group does not exist on this host' -Source 'local groups'
        }

        $groups += [pscustomobject] $entry
    }
    return $groups
}

function Get-RedirectionsXml {
    param([string] $Folder)
    $r = [ordered]@{ folder = $Folder; file = $null; found = $false; content = $null; error = $null }
    if ([string]::IsNullOrWhiteSpace($Folder)) {
        Add-CollectorStatus -Name 'redirections.xml' -Status 'skipped' -Detail 'RedirXMLSourceFolder is not set on this host' -Source 'registry'
        return [pscustomobject] $r
    }
    try {
        $file = Join-Path $Folder 'redirections.xml'
        $r.file = $file
        if (Test-Path -LiteralPath $file -ErrorAction Stop) {
            $r.found = $true
            $r.content = (Get-Content -LiteralPath $file -Raw -ErrorAction Stop)
            Add-CollectorStatus -Name 'redirections.xml' -Status 'ok' -Detail ('{0} characters' -f ([string] $r.content).Length) -Source $file
        } else {
            Add-CollectorStatus -Name 'redirections.xml' -Status 'absent' -Detail 'the configured folder holds no redirections.xml' -Source $file
        }
    } catch {
        $r.error = $_.Exception.Message
        Add-CollectorStatus -Name 'redirections.xml' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source ([string] $r.file)
    }
    return [pscustomobject] $r
}

function Get-AppMaskingRules {
    $dir = Join-Path $env:ProgramFiles 'FSLogix\Apps\Rules'
    $out = @()
    try {
        if (-not (Test-Path -LiteralPath $dir -ErrorAction Stop)) {
            Add-CollectorStatus -Name 'App Masking rules' -Status 'absent' -Detail 'the Rules folder does not exist' -Source $dir
            return $out
        }
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop | Sort-Object Name)) {
            $out += [pscustomobject] [ordered]@{ name = $f.Name; sizeBytes = $f.Length; modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
        }
        $st = 'ok'
        if ($out.Count -eq 0) { $st = 'empty' }
        Add-CollectorStatus -Name 'App Masking rules' -Status $st -Detail ('{0} file(s)' -f $out.Count) -Source $dir
    } catch {
        Add-CollectorStatus -Name 'App Masking rules' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source $dir
    }
    return $out
}

function Get-PolicyEvidence {
    # FSLogix's own ADMX writes into the product keys, so a GPO-set value is not visibly
    # different in the registry. The policy files are the one local trace we can read
    # without a domain round trip.
    $out = @()
    $script:PolicyScan = [pscustomobject] [ordered]@{ scanned = 0; unreadable = 0; hits = 0; error = $null }
    $root = Join-Path $env:windir 'System32\GroupPolicy'
    try {
        if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) {
            Add-CollectorStatus -Name 'Group Policy files' -Status 'absent' -Detail 'no GroupPolicy folder on this host' -Source $root
            return $out
        }
        foreach ($pol in (Get-ChildItem -LiteralPath $root -Filter 'registry.pol' -Recurse -File -ErrorAction SilentlyContinue)) {
            $script:PolicyScan.scanned++
            try {
                $bytes = [System.IO.File]::ReadAllBytes($pol.FullName)
                $text  = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($text -match 'FSLogix') {
                    $script:PolicyScan.hits++
                    $out += [pscustomobject] [ordered]@{ file = $pol.FullName; modified = $pol.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
                }
            } catch {
                $script:PolicyScan.unreadable++
            }
        }
        $st = 'ok'
        if ($script:PolicyScan.unreadable -gt 0) { $st = 'denied' }
        elseif ($script:PolicyScan.scanned -eq 0) { $st = 'empty' }
        Add-CollectorStatus -Name 'Group Policy files' -Status $st `
            -Detail ('{0} file(s) scanned, {1} unreadable, {2} mentioning FSLogix -- local policy only, a domain or Intune assignment leaves no file here' -f $script:PolicyScan.scanned, $script:PolicyScan.unreadable, $script:PolicyScan.hits) `
            -Source $root
    } catch {
        $script:PolicyScan.error = $_.Exception.Message
        Add-CollectorStatus -Name 'Group Policy files' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source $root
    }
    return $out
}

function Get-Capture {
    param([switch] $WithPathTests, [switch] $WithGpResult)

    Write-Verbose 'Reading the FSLogix registry keys'
    $keys = @()
    foreach ($areaName in $script:Areas.Keys) {
        $area = $script:Areas[$areaName]
        $keys += Read-RegistryArea -Path $area.ProductKey -Area $areaName -Scope 'product'
        $keys += Read-RegistryArea -Path $area.PolicyKey  -Area $areaName -Scope 'policy'
    }

    $services = @()
    $svcError = $null
    foreach ($svc in 'frxsvc','frxccds','frxdrv','frxdrvvt') {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            $services += [pscustomobject] [ordered]@{ name = $svc; status = [string] $s.Status; startType = [string] $s.StartType }
        } catch {
            if ((Get-ErrorKind $_) -eq 'denied') { $svcError = $_.Exception.Message }
        }
    }
    if ($svcError) {
        Add-CollectorStatus -Name 'FSLogix services' -Status 'denied' -Detail $svcError -Source 'service control manager'
    } elseif ($services.Count -eq 0) {
        Add-CollectorStatus -Name 'FSLogix services' -Status 'absent' -Detail 'none of the FSLogix services exist here' -Source 'service control manager'
    } else {
        Add-CollectorStatus -Name 'FSLogix services' -Status 'ok' -Detail ('{0} of 4 present' -f $services.Count) -Source 'service control manager'
    }

    $redirFolder = $null
    foreach ($k in $keys) {
        if ($k.area -ne 'Profiles') { continue }
        foreach ($v in (ConvertTo-Array $k.values)) {
            if ($v.name -eq 'RedirXMLSourceFolder' -and $v.display) { $redirFolder = [string] $v.display }
        }
    }

    $pathTests = @()
    if ($WithPathTests) {
        $seen = @{}
        foreach ($k in $keys) {
            foreach ($v in (ConvertTo-Array $k.values)) {
                if ($v.name -notin @('VHDLocations','CCDLocations')) { continue }
                foreach ($p in (([string] $v.display) -split "[`n;,]")) {
                    $p = $p.Trim()
                    if (-not $p) { continue }
                    if ($p -match '^type=') { continue }   # Cloud Cache provider strings
                    $probe = Get-TestablePath $p
                    if (-not $probe) { continue }
                    if ($seen.ContainsKey($probe.ToLowerInvariant())) { continue }
                    $seen[$probe.ToLowerInvariant()] = $true

                    Write-Verbose ("Probing {0}" -f $probe)
                    $note = $null
                    if ($probe -ne $p.TrimEnd('\')) { $note = 'the configured path holds an FSLogix variable, so the share itself was probed' }

                    # An unreachable SMB host is the one case that used to take minutes.
                    if ($probe -match '^\\\\([^\\]+)\\') {
                        if (-not (Test-SmbHostReachable -HostName $Matches[1])) {
                            $pathTests += [pscustomobject] [ordered]@{ area = $k.area; value = $v.name; path = $p; tested = $probe; reachable = $false; note = ('no answer on SMB (TCP 445) from {0} within 3 seconds' -f $Matches[1]) }
                            continue
                        }
                    }
                    $res = Test-PathBounded -Path $probe
                    if ($res.timedOut) { $note = 'the check was still waiting after 15 seconds and was given up' }
                    $pathTests += [pscustomobject] [ordered]@{ area = $k.area; value = $v.name; path = $p; tested = $probe; reachable = $res.reachable; note = $note }
                }
            }
        }
        $bad = @($pathTests | Where-Object { -not $_.reachable }).Count
        Add-CollectorStatus -Name 'Path reachability' -Status $(if ($pathTests.Count -eq 0) { 'empty' } else { 'ok' }) `
            -Detail ('{0} path(s) probed, {1} unreachable' -f $pathTests.Count, $bad) -Source 'profile paths'
    }

    $gpResult = $null
    if ($WithGpResult) {
        Write-Verbose 'Running gpresult'
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $raw  = & gpresult.exe /scope computer /r 2>&1
            $code = $LASTEXITCODE
            $text = ($raw | Out-String)
            # Computer-scope RSoP normally needs an elevated run. Before this, it failed into
            # silence and the report simply had no GPO section -- which reads like "no GPOs".
            if ($code -ne 0 -or $text -match 'does not have RSOP data|Access is denied|Zugriff verweigert') {
                $first = (($text -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
                Add-CollectorStatus -Name 'Applied GPO list' -Status 'denied' `
                    -Detail ('gpresult exited with {0}: {1} Computer-scope policy data normally needs an elevated run.' -f $code, ([string] $first).Trim()) -Source 'gpresult.exe'
            } elseif ([string]::IsNullOrWhiteSpace($text)) {
                Add-CollectorStatus -Name 'Applied GPO list' -Status 'empty' -Detail 'gpresult produced no output' -Source 'gpresult.exe'
            } else {
                $gpResult = $text
                Add-CollectorStatus -Name 'Applied GPO list' -Status 'ok' -Detail ('{0} characters' -f $text.Length) -Source 'gpresult.exe'
            }
        } catch {
            Add-CollectorStatus -Name 'Applied GPO list' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source 'gpresult.exe'
        } finally {
            $ErrorActionPreference = $prev
        }
    }

    $os = $null
    try {
        $ci = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $os = ('{0} (build {1})' -f $ci.Caption, $ci.BuildNumber)
    } catch {
        Add-CollectorStatus -Name 'Operating system' -Status (Get-ErrorKind $_) -Detail $_.Exception.Message -Source 'Win32_OperatingSystem'
    }

    $join            = Get-JoinState
    $version         = Get-FSLogixVersion
    $groups          = Get-FSLogixGroups
    $redirections    = Get-RedirectionsXml -Folder $redirFolder
    $appMaskingRules = Get-AppMaskingRules
    $policyEvidence  = Get-PolicyEvidence

    if (-not $WithPathTests)  { Add-CollectorStatus -Name 'Path reachability' -Status 'skipped' -Detail 'not requested (-TestPaths)' -Source 'profile paths' }
    if (-not $WithGpResult)   { Add-CollectorStatus -Name 'Applied GPO list'  -Status 'skipped' -Detail 'not requested (-IncludeGpResult)' -Source 'gpresult.exe' }

    return [pscustomobject] [ordered]@{
        schema          = $script:SchemaVersion
        toolVersion     = $script:ToolVersion
        capturedAt      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        computerName    = $env:COMPUTERNAME
        runAs           = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        elevated        = (Test-IsElevated)
        os              = $os
        join            = $join
        fslogixVersion  = $version
        services        = $services
        keys            = $keys
        groups          = $groups
        redirections    = $redirections
        appMaskingRules = $appMaskingRules
        policyEvidence  = @($policyEvidence)
        policyScan      = $script:PolicyScan
        pathTests       = $pathTests
        gpResult        = $gpResult
        collectors      = $script:Collectors
    }
}

# --------------------------------------------------------------------------------------
# Model: capture + catalogue -> rows and paste blocks
# --------------------------------------------------------------------------------------
function Format-AdvancedLine {
    param([string] $Name, [string] $Kind, $Data, [string] $Display)

    switch ($Kind) {
        'DWord' {
            $n = 0
            try { $n = [uint32] $Data } catch { try { $n = [uint32] $Display } catch { } }
            return ('"{0}"=dword:{1}' -f $Name, ('{0:x8}' -f $n))
        }
        'String'       { return ('"{0}"="{1}"' -f $Name, ($Display -replace '"', '\"')) }
        'ExpandString' { return ('"{0}"="{1}"' -f $Name, ($Display -replace '"', '\"')) }
        default        { return $null }
    }
}

function Build-Model {
    param($Capture, $Catalog)

    $areas = @()
    $findings = @()

    foreach ($areaName in $script:Areas.Keys) {
        $areaDef     = $script:Areas[$areaName]
        $rows        = @()
        $paste       = @()
        $pastePolicy = @()
        $hasPolicyKey = $false

        foreach ($k in (ConvertTo-Array $Capture.keys)) {
            if ($k.area -ne $areaName) { continue }
            if (-not $k.exists) { continue }
            if ($k.scope -eq 'policy') { $hasPolicyKey = $true }

            foreach ($v in (ConvertTo-Array $k.values)) {
                $entry = $null
                $ck = ('{0}|{1}' -f $areaName, $v.name).ToUpperInvariant()
                if ($Catalog.ContainsKey($ck)) { $entry = $Catalog[$ck] }

                $class = $areaDef.DefaultClass
                if ($entry) { $class = [string] (Get-Prop $entry 'Class' $areaDef.DefaultClass) }

                $meaning = $null
                $enum = Get-Prop $entry 'Enum'
                if ($enum) {
                    $key = [string] $v.display
                    if ($enum -is [System.Collections.IDictionary]) {
                        if ($enum.Contains($key)) { $meaning = [string] $enum[$key] }
                    } else {
                        $meaning = [string] (Get-Prop $enum $key)
                    }
                }

                $line = $null
                if ($class -eq 'registry' -or $class -eq 'editor') {
                    $line = Format-AdvancedLine -Name $v.name -Kind $v.kind -Data $v.data -Display $v.display
                    if ($line) {
                        # Policy values are kept in their own block: pasting them together with
                        # the product values would set the same name twice, with two answers.
                        if ($k.scope -eq 'policy') { $pastePolicy += $line } else { $paste += $line }
                    }
                }

                $rows += [pscustomobject] [ordered]@{
                    name      = $v.name
                    kind      = $v.kind
                    display   = [string] $v.display
                    meaning   = $meaning
                    scope     = $k.scope
                    class     = $class
                    field     = [string] (Get-Prop $entry 'Field')
                    note      = [string] (Get-Prop $entry 'Note')
                    doc       = [string] (Get-Prop $entry 'Doc')
                    known     = [bool] $entry
                    pasteLine = $line
                }

                # An empty value has nothing to carry over, so it is not a finding -- only a
                # value that holds something the Advanced editor cannot express is.
                if (($class -eq 'registry' -or $class -eq 'editor') -and -not $line -and -not [string]::IsNullOrEmpty([string] $v.display)) {
                    $findings += [pscustomobject] @{
                        severity = 'info'
                        title    = ('{0}\{1} cannot be typed into the Advanced editor' -f $areaName, $v.name)
                        body     = ('The value is of type {0}. Enter it under "All settings", or reproduce it with a scripted action. Current value: {1}' -f $v.kind, $v.display)
                    }
                }
            }
        }

        if ($hasPolicyKey) {
            $findings += [pscustomobject] @{
                severity = 'warn'
                title    = ('A Policies key exists for {0}' -f $areaDef.Title)
                body     = ('HKLM\SOFTWARE\Policies\FSLogix\{0} is present on this host. Values there come from Group Policy or Intune and are re-applied on every policy refresh -- they will overwrite what Nerdio Manager writes. They are listed separately below; decide per value which configuration you want to keep before you paste anything.' -f $areaName)
            }
        }

        # The same value name on both keys with two different answers is the case that
        # quietly breaks a rebuilt configuration, so it gets named here.
        foreach ($grp in ($rows | Group-Object -Property name)) {
            $prod = @($grp.Group | Where-Object { $_.scope -ne 'policy' })
            $pol  = @($grp.Group | Where-Object { $_.scope -eq 'policy' })
            if ($prod.Count -gt 0 -and $pol.Count -gt 0 -and $prod[0].display -ne $pol[0].display) {
                $findings += [pscustomobject] @{
                    severity = 'warn'
                    title    = ('{0}\{1} is set twice, with different values' -f $areaDef.Title, $grp.Name)
                    body     = ('The product key says "{0}", the Policies key says "{1}". Only one of them is what the environment actually runs on -- settle that before rebuilding the profile in Nerdio Manager, otherwise the value you type there is the one that loses.' -f $prod[0].display, $pol[0].display)
                }
            }
        }

        $areas += [pscustomobject] [ordered]@{
            name        = $areaName
            title       = $areaDef.Title
            blurb       = $areaDef.Blurb
            nmeTarget   = $areaDef.NmeTarget
            rows        = $rows
            paste       = $paste
            pastePolicy = $pastePolicy
        }
    }

    # --- findings that come from the whole picture ---------------------------------------
    $policyFiles = ConvertTo-Array $Capture.policyEvidence
    $policyScan  = Get-Prop $Capture 'policyScan'
    if ($policyFiles.Count -gt 0) {
        $findings += [pscustomobject] @{
            severity = 'warn'
            title    = 'Group Policy on this host mentions FSLogix'
            body     = ('{0} policy file(s) under %WINDIR%\System32\GroupPolicy reference FSLogix: {1}. FSLogix''s own ADMX writes into the same registry keys the product uses, so a GPO-set value looks exactly like a locally set one -- and it wins after every policy refresh. The help centre is explicit: session hosts should not receive conflicting FSLogix configurations from GPOs.' -f $policyFiles.Count, (($policyFiles | ForEach-Object { $_.file }) -join ', '))
        }
    } elseif ($policyScan -and (Get-Prop $policyScan 'scanned')) {
        $unreadable = [int] (Get-Prop $policyScan 'unreadable' 0)
        $body = ('{0} policy file(s) were scanned and none mentions FSLogix.' -f (Get-Prop $policyScan 'scanned'))
        if ($unreadable -gt 0) { $body += (' {0} of them could not be read with these rights, so this is not a clean result.' -f $unreadable) }
        $body += ' Note what this check can and cannot see: only local Group Policy leaves a file here. A domain GPO or an Intune policy writes straight into the registry, so silence here does not mean no policy -- the Policies key is the signal that does.'
        $findings += [pscustomobject] @{
            severity = $(if ($unreadable -gt 0) { 'warn' } else { 'info' })
            title    = 'No FSLogix mention in the local policy files'
            body     = $body
        }
    }

    # A collector that was blocked must say so. Otherwise "nothing found" and "not allowed to
    # look" are the same sentence, which is the one failure this report cannot afford.
    foreach ($c in (ConvertTo-Array (Get-Prop $Capture 'collectors'))) {
        if ($c.status -ne 'denied' -and $c.status -ne 'error') { continue }
        $findings += [pscustomobject] @{
            severity = 'warn'
            title    = ('Could not read: {0}' -f $c.name)
            body     = ('{0} ({1}). Whatever this would have shown is missing from the report -- absent and unreadable look the same everywhere else, so treat this part as unknown rather than empty.{2}' -f `
                        $c.detail, $c.source, $(if ($Capture.elevated -eq $false) { ' This run was not elevated; an elevated run may get further.' } else { '' }))
        }
    }

    $rules = ConvertTo-Array $Capture.appMaskingRules
    if ($rules.Count -gt 0) {
        $findings += [pscustomobject] @{
            severity = 'unmanaged'
            title    = ('{0} App Masking rule file(s) on this host' -f $rules.Count)
            body     = ('Nerdio Manager configures the FSLogix profile and Office containers; App Masking rule sets are not part of that configuration. Carry them over with a scripted action or your image build. Files: {0}' -f (($rules | ForEach-Object { $_.name }) -join ', '))
        }
    }

    $redir = $Capture.redirections
    if ($redir -and (Get-Prop $redir 'found')) {
        $findings += [pscustomobject] @{
            severity = 'info'
            title    = 'redirections.xml is in use'
            body     = ('The host reads its redirections from {0}. In Nerdio Manager this becomes the "Redirections" toggle on the FSLogix profile; the file content is reproduced at the end of this report so it can be pasted there.' -f (Get-Prop $redir 'file'))
        }
    }

    foreach ($g in (ConvertTo-Array $Capture.groups)) {
        $gErr = [string] (Get-Prop $g 'error')
        if ($gErr -and $gErr -ne 'group not found') {
            $findings += [pscustomobject] @{
                severity = 'warn'
                title    = ('"{0}" could not be read' -f $g.name)
                body     = ('{0} Who the containers apply to is therefore unknown in this report -- it is not the same as "applies to everyone".' -f $gErr)
            }
            continue
        }
        if (-not (Get-Prop $g 'exists')) { continue }
        $members = ConvertTo-Array (Get-Prop $g 'members')
        if ($members.Count -eq 0) { continue }

        # "Everyone" (S-1-1-0) is what the FSLogix installer itself puts in the include lists.
        # Treating that as a finding to act on sends people hunting for a difference that is
        # the default. Localised installs name it differently, so match the SID as well.
        $sids = ConvertTo-Array (Get-Prop $g 'memberSids')
        $hasEveryone = ($sids -contains 'S-1-1-0')
        if (-not $hasEveryone) {
            foreach ($m in $members) { if ($m -match '(^|\\)(Everyone|Jeder)$') { $hasEveryone = $true } }
        }
        $others = @($members | Where-Object { $_ -notmatch '(^|\\)(Everyone|Jeder)$' })
        $isExclude = ([string] $g.name) -like '*Exclude*'

        if ($isExclude) {
            $findings += [pscustomobject] @{
                severity = 'info'
                title    = ('"{0}" has {1} member(s)' -f $g.name, $members.Count)
                body     = ('Members: {0}. Nerdio Manager has two checkboxes for the common cases -- "Exclude the local admin accounts from FSLogix" and "Exclude domain accounts from FSLogix" (which takes the domain in a box below). Anything else in this group has to be reproduced by hand or with a scripted action.' -f ($members -join ', '))
            }
        } elseif ($hasEveryone -and $others.Count -eq 0) {
            $findings += [pscustomobject] @{
                severity = 'info'
                title    = ('"{0}" contains Everyone -- the default' -f $g.name)
                body     = 'This is what the FSLogix installer puts there: the containers apply to all users, minus whoever is in the matching exclude list. Nothing to reproduce in Nerdio Manager.'
            }
        } elseif ($hasEveryone) {
            $findings += [pscustomobject] @{
                severity = 'info'
                title    = ('"{0}" has Everyone and {1} more member(s)' -f $g.name, $others.Count)
                body     = ('Everyone is already in the list, so the containers apply to all users and the extra entries ({0}) change nothing today. Worth a look only if someone meant to narrow the scope and left Everyone in by accident.' -f ($others -join ', '))
            }
        } else {
            $findings += [pscustomobject] @{
                severity = 'warn'
                title    = ('"{0}" is narrowed to {1} member(s)' -f $g.name, $members.Count)
                body     = ('Members: {0} -- and not Everyone, so FSLogix applies to those members only. Nerdio Manager does not manage include-list membership; reproduce it with a scripted action, or the containers will apply to everyone in the new environment.' -f ($members -join ', '))
            }
        }
    }

    foreach ($t in (ConvertTo-Array $Capture.pathTests)) {
        if ($t.reachable) { continue }
        $tested = [string] (Get-Prop $t 'tested')
        if (-not $tested) { $tested = [string] $t.path }
        $body = ('Configured as {0}\{1}: {2}' -f $t.area, $t.value, $t.path)
        if ($tested -ne [string] $t.path) { $body += ('. Probed: {0}' -f $tested) }
        $tNote = [string] (Get-Prop $t 'note')
        if ($tNote) { $body += (' -- {0}' -f $tNote) }
        $body += '. Checked from this session host with the rights of whoever ran this, at capture time; it may still be correct for the target environment.'
        $findings += [pscustomobject] @{
            severity = 'warn'
            title    = ('Path not reachable from this host: {0}' -f $tested)
            body     = $body
        }
    }

    $join = $Capture.join
    if ($join -and (Get-Prop $join 'entraJoined') -and -not (Get-Prop $join 'domainJoined')) {
        $findings += [pscustomobject] @{
            severity = 'info'
            title    = 'Entra ID joined host'
            body     = 'For Azure Files with Entra ID Kerberos, use the NME checkbox "Configure session hosts registry for Entra ID joined storage" instead of copying AccessNetworkAsComputerObject by hand.'
        }
    }

    if (-not $Capture.fslogixVersion) {
        $findings += [pscustomobject] @{
            severity = 'info'
            title    = 'No FSLogix agent found on this host'
            body     = 'frxsvc.exe was not found under Program Files. The registry values below may be a prepared configuration rather than a running one.'
        }
    }

    return [pscustomobject] @{ areas = $areas; findings = $findings }
}

# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------
function New-HtmlReport {
    param($Capture, $Model)

    $sb = New-Object System.Text.StringBuilder
    function Add-Line([string] $s) { [void] $sb.AppendLine($s) }

    $host_   = Protect-Html ([string] $Capture.computerName)
    $when    = Protect-Html ([string] $Capture.capturedAt)
    $version = [string] $Capture.fslogixVersion
    $os      = [string] $Capture.os

    $joinText = 'unknown'
    $join = $Capture.join
    if ($join) {
        if ((Get-Prop $join 'domainJoined') -and (Get-Prop $join 'entraJoined')) { $joinText = 'Entra ID hybrid joined' }
        elseif (Get-Prop $join 'entraJoined')  { $joinText = 'Entra ID joined' }
        elseif (Get-Prop $join 'domainJoined') { $joinText = 'Active Directory domain joined' }
        else { $joinText = 'workgroup' }
    }

    $totalValues = 0; $fieldCount = 0; $pasteCount = 0; $unknownCount = 0
    foreach ($a in $Model.areas) {
        $totalValues += @($a.rows).Count
        $pasteCount  += @($a.paste).Count
        foreach ($r in $a.rows) {
            if ($r.class -eq 'field') { $fieldCount++ }
            if (-not $r.known) { $unknownCount++ }
        }
    }
    $warnCount = @($Model.findings | Where-Object { $_.severity -eq 'warn' }).Count

    Add-Line '<!doctype html>'
    Add-Line '<html lang="en"><head><meta charset="utf-8">'
    Add-Line '<meta name="viewport" content="width=device-width, initial-scale=1">'
    Add-Line ('<title>FSLogix to Nerdio - {0}</title>' -f $host_)
    Add-Line @'
<style>
:root{
  --bg:#f7f7f8; --card:#fff; --ink:#15171a; --muted:#5c6470; --line:#e2e5ea;
  --accent:#2d5bd7; --warn-bg:#fff6e5; --warn-line:#e0a325; --warn-ink:#6b4a00;
  --gray-bg:#f0f1f3; --code-bg:#f4f5f7; --ok:#1f7a4d;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#121417; --card:#191c21; --ink:#e8eaed; --muted:#9aa3af; --line:#2a2f37;
    --accent:#86a8ff; --warn-bg:#2d2411; --warn-line:#b5861f; --warn-ink:#f0d9a4;
    --gray-bg:#20242b; --code-bg:#15181d; --ok:#5fd199;
  }
}
*{box-sizing:border-box}
body{margin:0;padding:0 16px 64px;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto}
header{padding:40px 0 20px;border-bottom:1px solid var(--line);margin-bottom:28px}
h1{font-size:27px;line-height:1.2;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:20px;margin:40px 0 4px;letter-spacing:-.01em}
h3{font-size:15px;margin:26px 0 8px}
.sub{color:var(--muted);margin:0}
.facts{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}
.fact{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:9px 14px;min-width:120px}
.fact b{display:block;font-size:21px;font-weight:600;line-height:1.2}
.fact span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
nav{margin:0 0 8px;font-size:14px}
nav a{color:var(--accent);text-decoration:none;margin-right:16px}
nav a:hover{text-decoration:underline}
.card{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:18px 20px;margin:14px 0}
p.lead{color:var(--muted);margin:4px 0 14px}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:10px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;
  letter-spacing:.04em;border-bottom:1px solid var(--line);padding:0 10px 7px 0}
td{border-bottom:1px solid var(--line);padding:9px 10px 9px 0;vertical-align:top}
td:last-child,th:last-child{padding-right:0}
tr.policy td{background:var(--warn-bg)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code-bg);border-radius:4px;padding:1px 5px;font-size:13px;overflow-wrap:anywhere}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:9px;padding:14px;
  overflow:auto;font-size:13px;line-height:1.5;margin:0}
.val{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;overflow-wrap:anywhere}
.muted{color:var(--muted)}
.note{color:var(--muted);font-size:13px;display:block;margin-top:3px}
.tag{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.03em;text-transform:uppercase;
  border-radius:5px;padding:2px 7px;white-space:nowrap}
.tag-field{background:rgba(45,91,215,.13);color:var(--accent)}
.tag-registry{background:var(--gray-bg);color:var(--muted)}
.tag-editor{background:var(--gray-bg);color:var(--muted)}
.tag-policy{background:rgba(224,163,37,.2);color:var(--warn-ink)}
.finding{border-left:3px solid var(--line);padding:2px 0 2px 14px;margin:16px 0}
.finding.warn{border-left-color:var(--warn-line)}
.finding.unmanaged{border-left-color:var(--muted)}
.finding b{display:block;margin-bottom:2px}
.finding p{margin:0;color:var(--muted);font-size:14px}
.copybar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 8px}
button.copy{font:inherit;font-size:13px;background:var(--card);color:var(--ink);border:1px solid var(--line);
  border-radius:7px;padding:5px 12px;cursor:pointer}
button.copy:hover{border-color:var(--accent);color:var(--accent)}
ol.steps{padding-left:20px} ol.steps li{margin:9px 0}
footer{margin-top:52px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
a{color:var(--accent)}
@media print{
  body{background:#fff;padding:0}
  .card{break-inside:avoid;border-color:#ccc}
  button.copy{display:none}
  nav{display:none}
  tr.policy td{background:#fff}
}
</style>
'@
    Add-Line '</head><body><div class="wrap">'

    # --- header -------------------------------------------------------------------------
    Add-Line '<header>'
    Add-Line ('<h1>FSLogix configuration of <code>{0}</code></h1>' -f $host_)
    $subParts = @("captured $when")
    if ($version) { $subParts += ('FSLogix ' + (Protect-Html $version)) } else { $subParts += 'no FSLogix agent found' }
    if ($os)      { $subParts += (Protect-Html $os) }
    $subParts += $joinText
    $runAs = [string] (Get-Prop $Capture 'runAs')
    $elev  = Get-Prop $Capture 'elevated'
    if ($runAs) {
        $elevText = 'elevation unknown'
        if ($elev -eq $true)  { $elevText = 'elevated' }
        if ($elev -eq $false) { $elevText = 'not elevated' }
        $subParts += ('run as {0} ({1})' -f $runAs, $elevText)
    }
    Add-Line ('<p class="sub">{0}</p>' -f (Protect-Html ($subParts -join '  &middot;  ')).Replace('&amp;middot;','&middot;'))
    Add-Line '<div class="facts">'
    Add-Line ('<div class="fact"><b>{0}</b><span>values found</span></div>' -f $totalValues)
    Add-Line ('<div class="fact"><b>{0}</b><span>named NME fields</span></div>' -f $fieldCount)
    Add-Line ('<div class="fact"><b>{0}</b><span>registry lines</span></div>' -f $pasteCount)
    Add-Line ('<div class="fact"><b>{0}</b><span>need a decision</span></div>' -f $warnCount)
    Add-Line '</div></header>'

    Add-Line '<nav><a href="#howto">How to rebuild</a><a href="#map">Setting map</a><a href="#paste">Paste blocks</a><a href="#findings">Findings</a><a href="#coverage">Coverage</a><a href="#extras">Groups &amp; files</a></nav>'

    # --- how to rebuild -------------------------------------------------------------------
    Add-Line '<h2 id="howto">How to rebuild this in Nerdio Manager</h2>'
    Add-Line '<div class="card"><ol class="steps">'
    Add-Line ('<li>Create the profile: <b>Cloud Desktops &gt; Azure Virtual Desktop &gt; Host Pool Profiles</b>, then <b>New profile &gt; FSLogix</b>, and in the <b>FSLogix Profiles storage</b> area select <b>Add</b>. (<a href="{0}">help centre</a>)</li>' -f $script:Doc.Settings)
    Add-Line '<li>Fill the named fields from the <a href="#map">setting map</a> below -- name, version, Cloud Cache, the Entra ID and exclusion checkboxes, and the profile path.</li>'
    Add-Line ('<li>Open <b>FSLogix Registry Options</b>. In <b>All settings</b> you can search a setting by its registry name and type the value; in <b>Advanced</b> you paste lines in the form <code>"ProfileType"=dword:00000003</code>. The <a href="#paste">paste blocks</a> below are already in that form. (<a href="{0}">help centre</a>)</li>' -f $script:Doc.Identity)
    Add-Line '<li>Repeat for the Office container if this host has one, and tick <b>Manage App Service settings</b> / <b>Manage Log settings</b> if those blocks are not empty.</li>'
    Add-Line ('<li>Assign it: per host pool under <b>Settings &gt; FSLogix</b>, or as the environment default under <b>System &gt; Settings &gt; Integrations</b>. Per-pool settings only reach newly created or re-imaged hosts. (<a href="{0}">help centre</a>)</li>' -f $script:Doc.PerPool)
    Add-Line '<li>Work through the <a href="#findings">findings</a> before you call it done -- Group Policy, include lists and App Masking are the three that silently undo the rest.</li>'
    Add-Line '</ol></div>'

    # --- setting map ----------------------------------------------------------------------
    Add-Line '<h2 id="map">Setting map</h2>'
    Add-Line '<p class="lead">Every value found on this host, and what it becomes in Nerdio Manager. Rows on a coloured background come from a Policies key.</p>'
    foreach ($a in $Model.areas) {
        if (@($a.rows).Count -eq 0) { continue }
        Add-Line '<div class="card">'
        Add-Line ('<h3>{0} <span class="muted">&mdash; {1}</span></h3>' -f (Protect-Html $a.title), (Protect-Html $a.nmeTarget))
        Add-Line ('<p class="lead">{0}</p>' -f (Protect-Html $a.blurb))
        Add-Line '<table><thead><tr><th style="width:24%">Setting</th><th style="width:26%">Value on this host</th><th style="width:14%">In Nerdio</th><th>Note</th></tr></thead><tbody>'
        foreach ($r in ($a.rows | Sort-Object @{Expression={ if ($_.scope -eq 'policy') { 1 } else { 0 } }}, @{Expression={$_.name}})) {
            $cls = ''
            if ($r.scope -eq 'policy') { $cls = ' class="policy"' }
            $valHtml = Protect-Html $r.display
            if ($r.meaning) { $valHtml += ('<span class="note">{0}</span>' -f (Protect-Html $r.meaning)) }

            switch ($r.class) {
                'field'     { $nme = ('<span class="tag tag-field">field</span><span class="note">{0}</span>' -f (Protect-Html $r.field)) }
                'registry'  { $nme = '<span class="tag tag-registry">registry</span><span class="note">Registry Options</span>' }
                'editor'    { $nme = ('<span class="tag tag-editor">editor</span><span class="note">{0}</span>' -f (Protect-Html $a.nmeTarget)) }
                'unmanaged' { $nme = '<span class="tag tag-registry">do not copy</span>' }
                default     { $nme = '<span class="tag tag-registry">registry</span>' }
            }
            if ($r.scope -eq 'policy') { $nme += ' <span class="tag tag-policy">from GPO</span>' }

            $note = ''
            if ($r.note) {
                $note = Protect-Html $r.note
            } elseif (-not $r.known) {
                # Say what actually happened to this value, not what usually happens to one.
                if ($r.pasteLine) {
                    $note = '<span class="muted">Not in the catalogue. It is carried over unchanged in the paste block below; check it against the Microsoft reference.</span>'
                } elseif ([string]::IsNullOrEmpty([string] $r.display)) {
                    $note = '<span class="muted">Not in the catalogue, and empty on this host -- nothing to carry over.</span>'
                } else {
                    $note = ('<span class="muted">Not in the catalogue, and a {0} has no form in the Advanced editor -- enter it under "All settings" if it matters here.</span>' -f (Protect-Html $r.kind))
                }
            }
            if ($r.doc) { $note += (' <a href="{0}">docs</a>' -f $r.doc) }

            Add-Line ('<tr{0}><td><code>{1}</code><span class="note">{2}</span></td><td class="val">{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
                $cls, (Protect-Html $r.name), (Protect-Html $r.kind), $valHtml, $nme, $note)
        }
        Add-Line '</tbody></table></div>'
    }

    # --- paste blocks ------------------------------------------------------------------
    Add-Line '<h2 id="paste">Paste blocks</h2>'
    Add-Line ('<p class="lead">These are the lines for NME''s <b>Advanced</b> edit mode, in the documented format (<code>"ValueName"=dword:ValueData</code> and <code>"ValueName"="ValueData"</code>). Values that NME has a named field for are deliberately not in here -- set those in the field, not twice. (<a href="{0}">help centre</a>)</p>' -f $script:Doc.Settings)
    $blockIndex = 0
    foreach ($a in $Model.areas) {
        $lines = @($a.paste)
        if ($lines.Count -gt 0) {
            $blockIndex++
            $id = ('block{0}' -f $blockIndex)
            Add-Line '<div class="card">'
            Add-Line ('<div class="copybar"><h3 style="margin:0">{0} <span class="muted">&mdash; {1}</span></h3><button class="copy" data-target="{2}">Copy {3} line(s)</button></div>' -f `
                (Protect-Html $a.title), (Protect-Html $a.nmeTarget), $id, $lines.Count)
            Add-Line ('<pre id="{0}">{1}</pre>' -f $id, (Protect-Html ($lines -join "`n")))
            Add-Line '</div>'
        }

        $polLines = @($a.pastePolicy)
        if ($polLines.Count -gt 0) {
            $blockIndex++
            $id = ('block{0}' -f $blockIndex)
            Add-Line '<div class="card">'
            Add-Line ('<div class="copybar"><h3 style="margin:0">{0} <span class="muted">&mdash; from the Policies key</span></h3><button class="copy" data-target="{1}">Copy {2} line(s)</button></div>' -f `
                (Protect-Html $a.title), $id, $polLines.Count)
            Add-Line '<p class="lead">These come from <code>HKLM\SOFTWARE\Policies\FSLogix</code>, so Group Policy or Intune puts them there and will put them back. Do not paste them next to the block above without deciding which value wins &mdash; where a name appears in both, the findings say so.</p>'
            Add-Line ('<pre id="{0}">{1}</pre>' -f $id, (Protect-Html ($polLines -join "`n")))
            Add-Line '</div>'
        }
    }
    if ($blockIndex -eq 0) {
        Add-Line '<div class="card"><p class="lead">Nothing to paste -- no registry values outside the named NME fields were found.</p></div>'
    }

    # --- findings -------------------------------------------------------------------------
    Add-Line '<h2 id="findings">Findings</h2>'
    $findings = @($Model.findings)
    if ($findings.Count -eq 0) {
        Add-Line '<div class="card"><p class="lead">Nothing that needs a decision. The configuration maps onto Nerdio Manager as it stands.</p></div>'
    } else {
        Add-Line '<div class="card">'
        # The second key is not decoration: Sort-Object is not stable, so without it two
        # findings of the same severity come out in a different order on 5.1 than on 7.x,
        # and two runs of the same host stop diffing cleanly.
        foreach ($f in ($findings | Sort-Object @{Expression={ switch ($_.severity) { 'warn' {0} 'unmanaged' {1} default {2} } }}, @{Expression={ [string] $_.title }})) {
            Add-Line ('<div class="finding {0}"><b>{1}</b><p>{2}</p></div>' -f (Protect-Html $f.severity), (Protect-Html $f.title), (Protect-Html $f.body))
        }
        Add-Line '</div>'
    }

    # --- coverage ---------------------------------------------------------------------------
    Add-Line '<h2 id="coverage">Coverage</h2>'
    $collectors = ConvertTo-Array (Get-Prop $Capture 'collectors')
    if ($collectors.Count -eq 0) {
        Add-Line '<div class="card"><p class="lead">This capture was taken with an older version of the tool, which did not record what it could read. Absent and unreadable cannot be told apart in it.</p></div>'
    } else {
        $denied = @($collectors | Where-Object { $_.status -eq 'denied' -or $_.status -eq 'error' }).Count
        Add-Line '<div class="card">'
        if ($denied -eq 0) {
            Add-Line '<p class="lead">Every collector either read its source or found nothing there. Where this report says a setting is absent, it is absent -- not merely out of reach.</p>'
        } else {
            Add-Line ('<p class="lead"><b>{0} of {1} collectors came back empty-handed for lack of access.</b> What they would have shown is unknown, not absent; the findings name each one.</p>' -f $denied, $collectors.Count)
        }
        Add-Line '<table><thead><tr><th style="width:34%">Collector</th><th style="width:12%">Result</th><th>Detail</th></tr></thead><tbody>'
        $order = @{ 'denied' = 0; 'error' = 1; 'empty' = 2; 'absent' = 3; 'skipped' = 4; 'ok' = 5 }
        foreach ($c in ($collectors | Sort-Object @{Expression={ $v = $order[[string] $_.status]; if ($null -eq $v) { 9 } else { $v } }}, @{Expression={$_.name}})) {
            $cls = ''
            if ($c.status -eq 'denied' -or $c.status -eq 'error') { $cls = ' class="policy"' }
            $detail = Protect-Html ([string] $c.detail)
            if ($c.source) { $detail += ('<span class="note">{0}</span>' -f (Protect-Html ([string] $c.source))) }
            Add-Line ('<tr{0}><td>{1}</td><td><span class="tag tag-registry">{2}</span></td><td>{3}</td></tr>' -f `
                $cls, (Protect-Html ([string] $c.name)), (Protect-Html ([string] $c.status)), $detail)
        }
        Add-Line '</tbody></table></div>'
    }

    # --- extras ----------------------------------------------------------------------------
    Add-Line '<h2 id="extras">Groups, redirections and rule files</h2>'

    $groups = @($Capture.groups | Where-Object { Get-Prop $_ 'exists' })
    Add-Line '<div class="card"><h3 style="margin-top:0">FSLogix local groups</h3>'
    if ($groups.Count -eq 0) {
        Add-Line '<p class="lead">None of the four FSLogix groups exist on this host, so the containers apply to everyone.</p>'
    } else {
        Add-Line '<table><thead><tr><th style="width:34%">Group</th><th>Members</th></tr></thead><tbody>'
        foreach ($g in $groups) {
            $members = ConvertTo-Array (Get-Prop $g 'members')
            $text = if ($members.Count -eq 0) { '<span class="muted">empty</span>' } else { Protect-Html ($members -join ', ') }
            Add-Line ('<tr><td><code>{0}</code></td><td>{1}</td></tr>' -f (Protect-Html $g.name), $text)
        }
        Add-Line '</tbody></table>'
    }
    Add-Line '</div>'

    $redir = $Capture.redirections
    if ($redir -and (Get-Prop $redir 'found')) {
        Add-Line '<div class="card">'
        Add-Line ('<div class="copybar"><h3 style="margin:0">redirections.xml <span class="muted">&mdash; Redirections toggle</span></h3><button class="copy" data-target="redirxml">Copy</button></div>')
        Add-Line ('<p class="lead"><code>{0}</code></p>' -f (Protect-Html ([string] (Get-Prop $redir 'file'))))
        Add-Line ('<pre id="redirxml">{0}</pre>' -f (Protect-Html ([string] (Get-Prop $redir 'content'))))
        Add-Line '</div>'
    }

    $rules = @($Capture.appMaskingRules)
    if ($rules.Count -gt 0) {
        Add-Line '<div class="card"><h3 style="margin-top:0">App Masking rule files <span class="muted">&mdash; not managed by Nerdio Manager</span></h3>'
        Add-Line '<table><thead><tr><th style="width:50%">File</th><th>Size</th><th>Modified</th></tr></thead><tbody>'
        foreach ($r in $rules) {
            # Thousands separators follow the machine's culture, so the same host rendered in
            # two places produced "1,806" and "1.806". The report is English; pin the format.
            $size = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:n0}', [double] $r.sizeBytes)
            Add-Line ('<tr><td><code>{0}</code></td><td>{1} bytes</td><td>{2}</td></tr>' -f (Protect-Html $r.name), $size, (Protect-Html ([string] $r.modified)))
        }
        Add-Line '</tbody></table></div>'
    }

    $svcs = @($Capture.services)
    if ($svcs.Count -gt 0) {
        Add-Line '<div class="card"><h3 style="margin-top:0">FSLogix services</h3><table><thead><tr><th style="width:34%">Service</th><th>Status</th><th>Start type</th></tr></thead><tbody>'
        foreach ($s in $svcs) {
            Add-Line ('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td></tr>' -f (Protect-Html $s.name), (Protect-Html ([string] $s.status)), (Protect-Html ([string] $s.startType)))
        }
        Add-Line '</tbody></table></div>'
    }

    if ($Capture.gpResult) {
        Add-Line '<div class="card"><h3 style="margin-top:0">Applied Group Policy objects</h3>'
        Add-Line ('<pre>{0}</pre></div>' -f (Protect-Html ([string] $Capture.gpResult)))
    }

    Add-Line ('<footer>Generated by <b>fslogix-to-nerdio</b> {0} on {1}. Read-only: nothing on this host was changed. Navigation paths and field names are taken from the Nerdio help centre; verify them against your own version. Not affiliated with, or endorsed by, Nerdio or Microsoft.</footer>' -f $script:ToolVersion, $when)

    Add-Line @'
</div>
<script>
document.addEventListener('click', function (e) {
  var b = e.target.closest ? e.target.closest('button.copy') : null;
  if (!b) return;
  var el = document.getElementById(b.getAttribute('data-target'));
  if (!el) return;
  var text = el.innerText;
  var done = function () { var o = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = o; }, 1400); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
  } else { fallback(text, done); }
  function fallback(t, cb) {
    var ta = document.createElement('textarea');
    ta.value = t; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); cb(); } catch (err) { }
    document.body.removeChild(ta);
  }
});
</script>
</body></html>
'@

    return $sb.ToString()
}

# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------
$catalog = Get-BuiltInCatalog
if ($CatalogPath) {
    if (-not (Test-Path -LiteralPath $CatalogPath)) { throw "Catalog file not found: $CatalogPath" }
    $json = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json
    foreach ($p in $json.PSObject.Properties) {
        $h = @{}
        foreach ($q in $p.Value.PSObject.Properties) { $h[$q.Name] = $q.Value }
        $catalog[$p.Name.ToUpperInvariant()] = $h
    }
    Write-Verbose ("Catalogue overridden from {0}" -f $CatalogPath)
}

if ($FromJson) {
    if (-not (Test-Path -LiteralPath $FromJson)) { throw "Capture file not found: $FromJson" }
    $capture = Get-Content -LiteralPath $FromJson -Raw | ConvertFrom-Json
    if ($capture.schema -ne $script:SchemaVersion) {
        Write-Warning ("Capture schema is '{0}', this tool writes '{1}'. Rendering anyway." -f $capture.schema, $script:SchemaVersion)
    }
} else {
    if (-not (Test-IsWindows)) {
        throw 'Collecting needs Windows. On another operating system, render an existing capture with -FromJson.'
    }
    Write-Host 'Reading the FSLogix configuration of this host...'
    if ($TestPaths)       { Write-Host '  -TestPaths: profile shares are probed, which can take a few seconds each.' }
    if ($IncludeGpResult) { Write-Host '  -IncludeGpResult: gpresult is run, which can take several seconds.' }
    $capture = Get-Capture -WithPathTests:$TestPaths -WithGpResult:$IncludeGpResult
    Write-Host ('Collected {0} source(s).' -f @($capture.collectors).Count)
}

if ($SaveJson) {
    # Serialise first, then write in one call: a failure then says which of the two broke,
    # instead of a pipeline that stops halfway with a half-written file.
    Write-Host 'Writing the capture...'
    Write-Verbose 'Serialising the capture'
    $json = ConvertTo-CaptureJson -Value $capture
    Write-Verbose ('Serialised {0} characters' -f $json.Length)
    $jsonPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location).Path, $SaveJson))
    Write-Verbose ('Writing {0}' -f $jsonPath)
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("Capture written to {0}" -f $jsonPath)
}

Write-Host 'Building the report...'

$model = Build-Model -Capture $capture -Catalog $catalog
$html  = New-HtmlReport -Capture $capture -Model $model

if (-not $OutputPath) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
    $name  = [string] $capture.computerName
    if (-not $name) { $name = 'host' }
    $OutputPath = Join-Path (Get-Location).Path ('fslogix-nerdio-{0}-{1}.html' -f $name, $stamp)
}

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $html, $enc)
Write-Host ("Report written to {0}" -f $OutputPath)

if (-not $NoLaunch -and (Test-IsWindows)) {
    try { Invoke-Item -LiteralPath $OutputPath } catch { }
}
