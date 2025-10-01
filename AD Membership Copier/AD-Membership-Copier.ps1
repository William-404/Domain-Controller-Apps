<<#
AD Membership Copier (GUI)
- Self-elevates to Admin and ensures STA for WinForms.
- Accepts sAMAccountName, UPN, CN, DN, or partial name (first or last).
- Lists direct memberships (security + distribution), excludes Domain Users.
- Adds missing memberships From -> To with confirmation.
#>

# --- Self-elevate & ensure STA for WinForms ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$IsSTA   = [System.Threading.Thread]::CurrentThread.ApartmentState -eq 'STA'
if (-not $IsAdmin -or -not $IsSTA) {
  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$PSCommandPath`"")
  Start-Process PowerShell -ArgumentList $args -Verb RunAs
  exit
}

# --- UI + AD deps ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module ActiveDirectory -ErrorAction Stop

# --- Bind to one DC (PDC Emulator) ---
$Server     = (Get-ADDomain).PDCEmulator
$BaseDN     = (Get-ADDomain).DistinguishedName
$DomUsersDN = "CN=Domain Users,CN=Users,$BaseDN"

# --- Helpers ---
function Get-FriendlyName {
  param([Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADUser]$User)
  $name = (("$($User.GivenName) $($User.sn)").Trim())
  if ($name)                 { return $name }
  elseif ($User.DisplayName) { return $User.DisplayName }
  else                       { return $User.SamAccountName }
}

# Robust DN guarantee for any object/string
function Ensure-UserHasDN {
  param([Parameter(Mandatory)]$User)

  function _has($o,$n){
    ($null -ne $o) -and
    ($o.PSObject.Properties.Match($n).Count -gt 0) -and
    ($null -ne $o.$n) -and ($o.$n -ne '')
  }

  # String (DN/UPN/sAM/guid) -> direct lookup
  if ($User -is [string]) {
    try {
      return Get-ADUser -Server $Server -Identity $User -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn -ErrorAction Stop
    } catch { }
  }

  # ADUser with a DN already?
  if ($User -is [Microsoft.ActiveDirectory.Management.ADUser]) {
    if (_has $User 'DistinguishedName') { return $User }
  }

  # Object with DN/Sam/UPN/Guid props?
  foreach ($prop in 'DistinguishedName','SamAccountName','UserPrincipalName','ObjectGUID','sAMAccountName') {
    if (_has $User $prop) {
      try {
        return Get-ADUser -Server $Server -Identity $User.$prop -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn -ErrorAction Stop
      } catch { }
    }
  }

  # Last-ditch: use its text as a search query
  $t = $User.ToString()
  if ($t -and $t -ne '[object]') {
    $c = Find-CandidateUsers -Query $t
    if ($c.Count -ge 1) { return $c[0] }
  }

  throw "Unable to resolve user to a DN."
}

# Search helper: DN / sAM / UPN / name (ANR + first/last/display)
function Find-CandidateUsers {
  param([Parameter(Mandatory)][string]$Query)
  $raw = $Query.Trim()
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

  if ($raw -match '^[cC][nN]=.+,(?:.+,)?[dD][cC]=') {
    try { return @(Get-ADUser -Identity $raw -Server $Server -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn -ErrorAction Stop) }
    catch { return @() }
  }

  $q = $raw.Replace("'", "''")
  $seen = @{}
  $out  = @()

  $exact = @( Get-ADUser -Server $Server -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn `
             -Filter "sAMAccountName -eq '$q' -or userPrincipalName -eq '$q' -or cn -eq '$q'" -ErrorAction SilentlyContinue )
  foreach($u in $exact){ if(-not $seen[$u.DistinguishedName]){ $seen[$u.DistinguishedName]=$true; $out+=$u } }

  $fuzzy = @( Get-ADUser -Server $Server -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn `
             -Filter "(anr -like '*$q*') -or (displayName -like '*$q*') -or (givenName -like '*$q*') -or (sn -like '*$q*')" `
             -ErrorAction SilentlyContinue | Select-Object -First 100 )
  foreach($u in $fuzzy){ if(-not $seen[$u.DistinguishedName]){ $seen[$u.DistinguishedName]=$true; $out+=$u } }

  return @($out)
}

function Resolve-User {
  param([Parameter(Mandatory)][string]$Query)

  if ([string]::IsNullOrWhiteSpace($Query)) { throw "Please enter a user identifier." }
  $raw = $Query.Trim()

  if ($raw -match '^[cC][nN]=.+,(?:.+,)?[dD][cC]=') {
    try {
      return Get-ADUser -Identity $raw -Server $Server -Properties SamAccountName,DistinguishedName -ErrorAction Stop
    } catch { throw "No user found with the supplied DN." }
  }

  $q = $raw.Replace("'", "''")

  $exact = @( Get-ADUser -Server $Server -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn `
             -Filter "sAMAccountName -eq '$q' -or userPrincipalName -eq '$q' -or cn -eq '$q'" `
             -ErrorAction SilentlyContinue )
  if ($exact.Count -eq 1) { return $exact[0] }
  if ($exact.Count -gt 1) { $cands = $exact }

  if (-not $cands) {
    $cands = @( Get-ADUser -Server $Server -Properties SamAccountName,DistinguishedName,DisplayName,GivenName,Sn `
               -Filter "(anr -like '*$q*') -or (displayName -like '*$q*') -or (givenName -like '*$q*') -or (sn -like '*$q*')" `
               -ErrorAction SilentlyContinue | Select-Object -First 100 )
  }

  if (-not $cands -or $cands.Count -eq 0) { throw "User '$Query' not found." }

  if ($cands.Count -gt 1) {
    $pickForm = New-Object System.Windows.Forms.Form
    $pickForm.Text = "Select user"
    $pickForm.StartPosition = "CenterParent"
    $pickForm.Size = New-Object System.Drawing.Size(500, 420)

    $list = New-Object System.Windows.Forms.ListBox
    $list.Dock = 'Fill'
    $list.HorizontalScrollbar = $true
    foreach ($u in $cands) {
      $label =
        if ($u.GivenName -or $u.SN) { (("$($u.GivenName) $($u.SN)").Trim()) }
        elseif ($u.DisplayName)     { $u.DisplayName }
        else                        { $u.SamAccountName }
      [void]$list.Items.Add($label)
    }

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = "OK"
    $ok.Dock = 'Bottom'
    $ok.Add_Click({ if ($list.SelectedIndex -ge 0) { $pickForm.Tag = $list.SelectedIndex; $pickForm.Close() } })

    $pickForm.Controls.Add($list)
    $pickForm.Controls.Add($ok)
    [void]$pickForm.ShowDialog()

    if ($pickForm.Tag -ne $null) { return $cands[$pickForm.Tag] }
    throw "Selection cancelled."
  }
  return ($cands | Select-Object -First 1)
}

function Get-DirectGroups {
  param([Parameter(Mandatory)][string]$UserDN)
  Get-ADGroup -LDAPFilter "(&(objectClass=group)(member=$UserDN))" `
              -SearchBase $BaseDN -Server $Server -ErrorAction Stop |
    Where-Object { $_.DistinguishedName -ne $DomUsersDN } |
    Sort-Object Name
}

function Populate-ListBox {
  param([System.Windows.Forms.ListBox]$ListBox, [array]$Groups)
  $ListBox.Items.Clear()
  foreach ($g in $Groups) { [void]$ListBox.Items.Add($g.Name) }
}

# --- Build UI ---
$form                 = New-Object Windows.Forms.Form
$form.Text            = "AD Membership Copier"
$form.StartPosition   = "CenterScreen"
$form.Size            = New-Object Drawing.Size(940, 520)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox     = $false

$lblFrom = New-Object Windows.Forms.Label
$lblFrom.Text = "Copy From:"
$lblFrom.Location = New-Object Drawing.Point(12,14)
$lblFrom.AutoSize = $true
$form.Controls.Add($lblFrom)

$txtFrom = New-Object System.Windows.Forms.ComboBox
$txtFrom.Location = New-Object Drawing.Point(90,10)
$txtFrom.Size     = New-Object Drawing.Size(260,24)
$txtFrom.DropDownStyle      = 'DropDown'
$txtFrom.AutoCompleteMode   = 'SuggestAppend'
$txtFrom.AutoCompleteSource = 'ListItems'
$form.Controls.Add($txtFrom)

$btnLoadFrom = New-Object Windows.Forms.Button
$btnLoadFrom.Text = "Load user"
$btnLoadFrom.Location = New-Object Drawing.Point(($txtFrom.Location.X + $txtFrom.Width + 10), 8)
$btnLoadFrom.Size = New-Object Drawing.Size(90,28)
$form.Controls.Add($btnLoadFrom)

$lblTo = New-Object Windows.Forms.Label
$lblTo.Text = "Copy To:"
$lblTo.Location = New-Object Drawing.Point(470,14)
$lblTo.AutoSize = $true
$form.Controls.Add($lblTo)

$txtTo = New-Object System.Windows.Forms.ComboBox
$txtTo.Location = New-Object Drawing.Point(530,10)
$txtTo.Size     = New-Object Drawing.Size(260,24)
$txtTo.DropDownStyle      = 'DropDown'
$txtTo.AutoCompleteMode   = 'SuggestAppend'
$txtTo.AutoCompleteSource = 'ListItems'
$form.Controls.Add($txtTo)

$btnLoadTo = New-Object Windows.Forms.Button
$btnLoadTo.Text = "Load user"
$btnLoadTo.Location   = New-Object Drawing.Point(($txtTo.Location.X   + $txtTo.Width   + 10), 8)
$btnLoadTo.Size = New-Object Drawing.Size(90,28)
$form.Controls.Add($btnLoadTo)

$grpFrom = New-Object Windows.Forms.GroupBox
$grpFrom.Text = "From user"
$grpFrom.Location = New-Object Drawing.Point(12,50)
$grpFrom.Size = New-Object Drawing.Size(440,360)
$form.Controls.Add($grpFrom)

$lstFrom = New-Object Windows.Forms.ListBox
$lstFrom.Location = New-Object Drawing.Point(10,20)
$lstFrom.Size = New-Object Drawing.Size(420,330)
$lstFrom.HorizontalScrollbar = $true
$grpFrom.Controls.Add($lstFrom)

$grpTo = New-Object Windows.Forms.GroupBox
$grpTo.Text = "To user"
$grpTo.Location = New-Object Drawing.Point(462,50)
$grpTo.Size = New-Object Drawing.Size(440,360)
$form.Controls.Add($grpTo)

$lstTo = New-Object Windows.Forms.ListBox
$lstTo.Location = New-Object Drawing.Point(10,20)
$lstTo.Size = New-Object Drawing.Size(420,330)
$lstTo.HorizontalScrollbar = $true
$grpTo.Controls.Add($lstTo)

$btnAdd = New-Object Windows.Forms.Button
$btnAdd.Text = "Add permissions"
$btnAdd.Location = New-Object Drawing.Point(12,420)
$btnAdd.Size = New-Object Drawing.Size(150,30)
$btnAdd.Enabled = $false
$form.Controls.Add($btnAdd)

$status = New-Object Windows.Forms.Label
$status.Text = "Ready."
$status.AutoSize = $true
$status.Location = New-Object Drawing.Point(180,426)
$form.Controls.Add($status)

# --- Dark mode palette ---
$bg     = [Drawing.Color]::FromArgb(30,30,30)
$bg2    = [Drawing.Color]::FromArgb(37,37,38)
$inputB = [Drawing.Color]::FromArgb(45,45,48)
$fg     = [Drawing.Color]::Gainsboro
$border = [Drawing.Color]::FromArgb(62,62,64)

$form.BackColor = $bg
$form.ForeColor = $fg
$lblFrom.ForeColor = $fg
$lblTo.ForeColor   = $fg
$status.ForeColor  = $fg
$txtFrom.BackColor = $inputB; $txtFrom.ForeColor = $fg
$txtTo.BackColor   = $inputB; $txtTo.ForeColor   = $fg
foreach ($btn in @($btnLoadFrom, $btnLoadTo, $btnAdd)) {
  $btn.FlatStyle = 'Flat'
  $btn.BackColor = $inputB
  $btn.ForeColor = $fg
  $btn.FlatAppearance.BorderColor = $border
}
foreach ($gb in @($grpFrom, $grpTo)) { $gb.BackColor = $bg; $gb.ForeColor = $fg }
$lstFrom.BackColor = $bg2; $lstFrom.ForeColor = $fg; $lstFrom.BorderStyle = 'FixedSingle'
$lstTo.BackColor   = $bg2; $lstTo.ForeColor   = $fg; $lstTo.BorderStyle   = 'FixedSingle'

# --- Dark title bar ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class DwmApi {
  [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(
    IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);
}
"@
try {
  $useDark = 1
  [void][DwmApi]::DwmSetWindowAttribute($form.Handle, 20, [ref]$useDark, 4)
  [void][DwmApi]::DwmSetWindowAttribute($form.Handle, 19, [ref]$useDark, 4)
} catch { }

# --- State ---
$state = [ordered]@{
  FromUser        = $null
  ToUser          = $null
  FromGroups      = @()
  ToGroups        = @()
  FromCandidates  = @()
  ToCandidates    = @()
}

# --- Events ---
$btnLoadFrom.Add_Click({
  try {
    $status.Text = "Searching source user..."; $form.Refresh()
    $cands = Find-CandidateUsers -Query $txtFrom.Text
    $cnt   = @($cands).Count
    if ($cnt -eq 0) { throw "User '$($txtFrom.Text)' not found." }

    if ($cnt -eq 1) {
      # single, load immediately and update UI
      $state.FromCandidates = @()
      $txtFrom.Items.Clear()

      $state.FromUser   = Ensure-UserHasDN (@($cands)[0])
      $state.FromGroups = Get-DirectGroups -UserDN $state.FromUser.DistinguishedName
      Populate-ListBox -ListBox $lstFrom -Groups $state.FromGroups
      $grpFrom.Text = "From user — " + (Get-FriendlyName $state.FromUser)
      $status.Text  = "Loaded source: " + (Get-FriendlyName $state.FromUser) + " — " + $state.FromGroups.Count + " groups."
    }
    else {
      # multiple, show inline dropdown
      $txtFrom.Items.Clear()
      $state.FromCandidates = @($cands)
      foreach ($u in $state.FromCandidates) { [void]$txtFrom.Items.Add( (Get-FriendlyName $u) ) }
      $txtFrom.DroppedDown = $true
      $status.Text = "Select a user from the dropdown…"
      return
    }
  } catch {
    $state.FromUser = $null; $state.FromGroups=@(); $lstFrom.Items.Clear(); $grpFrom.Text="From user"
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,"Load source failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    $status.Text = "Failed to load source."
  }
  $btnAdd.Enabled = [bool]($state.FromUser -and $state.ToUser)
})

# Defensive: resolve via candidate array *or* the current text if array is misaligned
$txtFrom.Add_SelectedIndexChanged({
  try {
    $idx = [int]$txtFrom.SelectedIndex
if ($idx -lt 0) { return }

$userObj = $null
$fc = @($state.FromCandidates)
if ($fc.Count -gt $idx) {
  $userObj = $fc[$idx]
} else {
  $res = Find-CandidateUsers -Query $txtFrom.Text
  if (@($res).Count -ge 1) { $userObj = @($res)[0] }
}
if ($null -eq $userObj) { throw "Could not resolve selection. Try typing more characters." }

$state.FromUser   = Ensure-UserHasDN $userObj
$state.FromGroups = Get-DirectGroups -UserDN $state.FromUser.DistinguishedName
    Populate-ListBox -ListBox $lstFrom -Groups $state.FromGroups
    $grpFrom.Text = "From user — " + (Get-FriendlyName $state.FromUser)
    $status.Text  = "Loaded source: " + (Get-FriendlyName $state.FromUser) + " — " + $state.FromGroups.Count + " groups."
  } catch {
    $state.FromUser = $null; $state.FromGroups=@(); $lstFrom.Items.Clear(); $grpFrom.Text="From user"
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,"Load source failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    $status.Text = "Failed to load source."
  }
  $btnAdd.Enabled = [bool]($state.FromUser -and $state.ToUser)
})

$btnLoadTo.Add_Click({
  try {
    $status.Text = "Searching target user..."; $form.Refresh()
    $cands = Find-CandidateUsers -Query $txtTo.Text
    $cnt   = @($cands).Count
    if ($cnt -eq 0) { throw "User '$($txtTo.Text)' not found." }

    if ($cnt -eq 1) {
      # single, load immediately and update UI
      $state.ToCandidates = @()
      $txtTo.Items.Clear()

      $state.ToUser   = Ensure-UserHasDN (@($cands)[0])
      $state.ToGroups = Get-DirectGroups -UserDN $state.ToUser.DistinguishedName
      Populate-ListBox -ListBox $lstTo -Groups $state.ToGroups
      $grpTo.Text = "To user — " + (Get-FriendlyName $state.ToUser)
      $status.Text = "Loaded target: " + (Get-FriendlyName $state.ToUser) + " — " + $state.ToGroups.Count + " groups."
    }
    else {
      # multiple, show inline dropdown
      $txtTo.Items.Clear()
      $state.ToCandidates = @($cands)
      foreach ($u in $state.ToCandidates) { [void]$txtTo.Items.Add( (Get-FriendlyName $u) ) }
      $txtTo.DroppedDown = $true
      $status.Text = "Select a user from the dropdown…"
      return
    }
  } catch {
    $state.ToUser = $null; $state.ToGroups=@(); $lstTo.Items.Clear(); $grpTo.Text="To user"
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,"Load target failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    $status.Text = "Failed to load target."
  }
  $btnAdd.Enabled = [bool]($state.FromUser -and $state.ToUser)
})


$txtTo.Add_SelectedIndexChanged({
  try {
    $idx = [int]$txtTo.SelectedIndex
if ($idx -lt 0) { return }

$userObj = $null
$tc = @($state.ToCandidates)
if ($tc.Count -gt $idx) {
  $userObj = $tc[$idx]
} else {
  $res = Find-CandidateUsers -Query $txtTo.Text
  if (@($res).Count -ge 1) { $userObj = @($res)[0] }
}
if ($null -eq $userObj) { throw "Could not resolve selection. Try typing more characters." }

$state.ToUser   = Ensure-UserHasDN $userObj
$state.ToGroups = Get-DirectGroups -UserDN $state.ToUser.DistinguishedName
    Populate-ListBox -ListBox $lstTo -Groups $state.ToGroups
    $grpTo.Text = "To user — " + (Get-FriendlyName $state.ToUser)
    $status.Text = "Loaded target: " + (Get-FriendlyName $state.ToUser) + " — " + $state.ToGroups.Count + " groups."
  } catch {
    $state.ToUser = $null; $state.ToGroups=@(); $lstTo.Items.Clear(); $grpTo.Text="To user"
    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,"Load target failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    $status.Text = "Failed to load target."
  }
  $btnAdd.Enabled = [bool]($state.FromUser -and $state.ToUser)
})

# Enter key triggers "Load user"
$txtFrom.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $btnLoadFrom.PerformClick() } })
$txtTo.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $btnLoadTo.PerformClick() } })

$btnAdd.Add_Click({
  if (-not ($state.FromUser -and $state.ToUser)) { return }

  $fromDns = $state.FromGroups | ForEach-Object { $_.DistinguishedName }
  $toDns   = $state.ToGroups   | ForEach-Object { $_.DistinguishedName }
  $missing = $fromDns | Where-Object { $_ -and ($_ -notin $toDns) -and ($_ -ne $DomUsersDN) }

  if (-not $missing -or $missing.Count -eq 0) {
    [System.Windows.Forms.MessageBox]::Show("Nothing to add. Target already has these direct memberships.",
      "Add permissions",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    return
  }

  $preview = ($missing | ForEach-Object { " - " + $_ }) -join "`r`n"
  $resp = [System.Windows.Forms.MessageBox]::Show(
    "Add the following " + $missing.Count + " group(s) to '" + $state.ToUser.SamAccountName + "'?`r`n`r`n" + $preview,
    "Confirm add",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
  if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }

  $status.Text = "Adding " + $missing.Count + " group(s)..."; $form.Refresh()
  $added = 0; $failed = @()
  foreach ($dn in $missing) {
    try {
      Add-ADGroupMember -Identity $dn -Members $state.ToUser.DistinguishedName -Server $Server -ErrorAction Stop
      $added++
    } catch {
      $failed += [pscustomobject]@{ GroupDN=$dn; Error=$_.Exception.Message }
    }
  }

  $state.ToGroups = Get-DirectGroups -UserDN $state.ToUser.DistinguishedName
  Populate-ListBox -ListBox $lstTo -Groups $state.ToGroups

  if ($failed.Count) {
    $msg = "Added " + $added + " group(s). Failed " + $failed.Count + ":" + "`r`n" +
           (($failed | ForEach-Object { " - " + $_.GroupDN + " -> " + $_.Error }) -join "`r`n")
    [System.Windows.Forms.MessageBox]::Show($msg,"Completed with errors",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    $status.Text = "Added " + $added + " group(s), " + $failed.Count + " failed."
  } else {
    [System.Windows.Forms.MessageBox]::Show("Success. Added " + $added + " group(s).","Completed",
      [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    $status.Text = "Done. Added " + $added + " group(s)."
  }
})

# --- Show UI ---
[void]$form.ShowDialog()
