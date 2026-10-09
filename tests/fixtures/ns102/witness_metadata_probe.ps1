# Opt-in dedicated-VM metadata spike. Never run on the physical host.
# No elevation, policy/service change, socket, executable launch or active rule.
param(
    [Parameter(Mandatory=$true)][string]$AuthorizedVm,
    [Parameter(Mandatory=$true)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
$report = [ordered]@{status='NOT_RUN'; stage='preflight'; cleanup='not_needed'}
$created = $false
$policy = $null
$ruleName = $null
$currentExpected = $null
$properties = @('Name','Description','Grouping','ApplicationName','ServiceName',
    'Protocol','LocalPorts','RemotePorts','LocalAddresses','RemoteAddresses',
    'IcmpTypesAndCodes','Direction','Profiles','Action','Enabled','InterfaceTypes',
    'EdgeTraversal','EdgeTraversalOptions','LocalAppPackageId','LocalUserOwner',
    'LocalUserAuthorizedList','RemoteUserAuthorizedList','RemoteMachineAuthorizedList','SecureFlags')
function Snapshot($rule) {
    $result = [ordered]@{}
    foreach ($property in $properties) { $result[$property] = $rule.$property }
    # Native successful empty values may be NULL BSTR/VT_EMPTY, not missing getters.
    foreach ($property in @('Description','Grouping','ServiceName','IcmpTypesAndCodes',
        'LocalAppPackageId','LocalUserOwner','LocalUserAuthorizedList',
        'RemoteUserAuthorizedList','RemoteMachineAuthorizedList')) {
        if ($null -eq $result[$property]) { $result[$property] = '' }
    }
    $result['Interfaces'] = @($rule.Interfaces | ForEach-Object { [string]$_ })
    return ($result | ConvertTo-Json -Depth 5 -Compress)
}
function ExactMatches($name) {
    $matches = @()
    $rules = $policy.Rules
    $count = $rules.Count
    if ($count -gt 16384) { throw 'enumeration bound' }
    $seen = 0
    foreach ($item in $rules) {
        $seen++
        if ($seen -gt 16384) { throw 'enumeration bound' }
        if ([string]::Equals($item.Name, $name, [StringComparison]::OrdinalIgnoreCase)) {
            $matches += $item
        }
    }
    if ($seen -ne $count -or $rules.Count -ne $count) { throw 'enumeration changed' }
    return $matches
}
function Inventory {
    $rows = @()
    $rules = $policy.Rules
    $count = $rules.Count
    if ($count -gt 16384) { throw 'inventory bound' }
    foreach ($item in $rules) {
        if ($rows.Count -ge 16384) { throw 'inventory bound' }
        $rows += (Snapshot $item)
    }
    if ($rows.Count -ne $count -or $rules.Count -ne $count) { throw 'inventory changed' }
    return (($rows | Sort-Object) -join "`n")
}
try {
    if ($env:COMPUTERNAME -cne $AuthorizedVm -or $AuthorizedVm -cne 'DESKTOP-B18OKSK') {
        throw 'dedicated VM identity required'
    }
    $system = Get-CimInstance Win32_ComputerSystem
    if ($system.Manufacturer -notmatch 'VMware' -or $system.Model -notmatch 'VMware') {
        throw 'physical host refused'
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'existing admin token required; do not elevate'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $report['build'] = $os.BuildNumber
    $report['vm'] = $env:COMPUTERNAME
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $before = Inventory
    $report['before_count'] = $policy.Rules.Count
    $report['stage'] = 'detached_construction'
    $identity = [guid]::NewGuid().ToString('D')
    $nonceBytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($nonceBytes)
    $rng.Dispose()
    $nonce = ([BitConverter]::ToString($nonceBytes)).Replace('-','').ToLowerInvariant()
    $marker = 'NetSentinel response witness v1 ' + $identity + ' ' + $nonce
    $ruleName = 'NetSentinel:NS102-metadata-spike:' + $identity
    # A nonexistent fixture path and Disabled rule cannot affect active traffic.
    $fixture = Join-Path $env:TEMP ('NetSentinel-NS102-metadata-fixture-' + $identity + '.exe')
    if (Test-Path -LiteralPath $fixture) { throw 'fixture unexpectedly exists' }
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Protocol = 6
    $rule.Name = $ruleName
    $rule.Description = $marker
    $rule.ApplicationName = $fixture
    $rule.RemoteAddresses = '8.8.8.8'
    $rule.RemotePorts = '443'
    $rule.LocalAddresses = '*'
    $rule.LocalPorts = '*'
    $rule.Profiles = 2
    $rule.Direction = 2
    $rule.Action = 0
    $rule.Enabled = $false
    $rule.InterfaceTypes = 'All'
    $rule.EdgeTraversal = $false
    $rule.EdgeTraversalOptions = 0
    $currentExpected = Snapshot $rule
    if (@(ExactMatches $ruleName).Count -ne 0) { throw 'identity collision' }
    $report['stage'] = 'add'
    $report['cleanup'] = 'unknown_add_outcome'
    $policy.Rules.Add($rule)
    $created = $true
    $report['cleanup'] = 'pending'
    $fresh = @(ExactMatches $ruleName)
    if ($fresh.Count -ne 1 -or (Snapshot $fresh[0]) -cne $currentExpected) { throw 'full initial readback mismatch' }
    $report['marker_characters'] = $marker.Length
    $report['marker_exact'] = [string]::Equals($fresh[0].Description, $marker, [StringComparison]::Ordinal)
    $report['enabled'] = $fresh[0].Enabled
    $report['stage'] = 'metadata_vectors'
    $unicode = 'NetSentinel metadata ' + [char]0x00D6 + 'rnek ' + [char]0x4E2D + ' ' + [char]0xD83D + [char]0xDEE1
    $vectors = @('', 'x', $unicode, ('x' * 4096), $marker)
    $passed = 0
    foreach ($description in $vectors) {
        $fresh = @(ExactMatches $ruleName)
        if ($fresh.Count -ne 1 -or (Snapshot $fresh[0]) -cne $currentExpected) { throw 'external drift' }
        # Verify the intended new complete snapshot before touching OS metadata.
        $expectedObject = $currentExpected | ConvertFrom-Json
        $expectedObject.Description = $description
        $nextExpected = $expectedObject | ConvertTo-Json -Depth 5 -Compress
        $fresh[0].Description = $description
        $currentExpected = $nextExpected
        $fresh = @(ExactMatches $ruleName)
        if ($fresh.Count -ne 1 -or (Snapshot $fresh[0]) -cne $currentExpected) { throw 'metadata readback mismatch' }
        if (-not [string]::Equals($fresh[0].Description, $description, [StringComparison]::Ordinal)) { throw 'description changed' }
        if ($fresh[0].Enabled) { throw 'disabled specimen became active' }
        $passed++
    }
    $report['roundtrip_vectors'] = $passed
    $report['unicode_exact'] = $true
    $report['ascii_4096_exact'] = $true
    $report['marker_restored_exact'] = $true
    $report['status'] = 'PASS'
} catch {
    $report['status'] = 'FAIL'
    if ($report['stage'] -eq 'add' -and -not $created) {
        $report['cleanup'] = 'UNRESOLVED_ADD_OUTCOME_NO_OWNERSHIP'
    }
    # No raw COM error, rule metadata, witness or local inventory in output.
} finally {
    if ($created) {
        try {
            $fresh = @(ExactMatches $ruleName)
            if ($fresh.Count -ne 1 -or (Snapshot $fresh[0]) -cne $currentExpected) {
                throw 'cleanup refuses drift or ambiguity'
            }
            $policy.Rules.Remove($ruleName)
            if (@(ExactMatches $ruleName).Count -ne 0) { throw 'cleanup absence unverified' }
            $report['cleanup'] = 'verified_absent'
            $report['after_count'] = $policy.Rules.Count
            $report['unrelated_inventory_equal'] = ((Inventory) -ceq $before)
            if (-not $report['unrelated_inventory_equal']) { $report['status'] = 'FAIL' }
        } catch {
            $report['cleanup'] = 'UNRESOLVED_DO_NOT_DELETE_BY_NAME'
            $report['status'] = 'FAIL'
        }
    }
    $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
    $fresh = $rule = $policy = $null
}
if ($report.status -ne 'PASS') { exit 1 }
