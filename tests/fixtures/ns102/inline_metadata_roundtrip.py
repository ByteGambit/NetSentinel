"""Reviewable individual native commands, executed ONLY through VMware MCP.

No native API is imported/called on the host. The JSON receipt is data, never an
executable script. Requires exact dedicated VM and an existing administrator.
One disabled test rule, no executable/socket/capture, no policy changes.
"""

import re


COMMON = r"""
$ErrorActionPreference='Stop';
if($env:COMPUTERNAME -cne 'DESKTOP-B18OKSK'){throw 'dedicated VM required'};
$cs=Get-CimInstance Win32_ComputerSystem;
if($cs.Manufacturer -notmatch 'VMware' -or $cs.Model -notmatch 'VMware'){throw 'physical host refused'};
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'existing admin token required'};
$p=New-Object -ComObject HNetCfg.FwPolicy2;
$props=@('Name','Description','Grouping','ApplicationName','ServiceName','Protocol','LocalPorts','RemotePorts','LocalAddresses','RemoteAddresses','IcmpTypesAndCodes','Direction','Profiles','Action','Enabled','InterfaceTypes','EdgeTraversal','EdgeTraversalOptions','LocalAppPackageId','LocalUserOwner','LocalUserAuthorizedList','RemoteUserAuthorizedList','RemoteMachineAuthorizedList','SecureFlags');
function Snap($r){
 $d=[ordered]@{};
 foreach($k in $props){$d[$k]=$r.$k};
 foreach($k in @('Description','Grouping','ServiceName','IcmpTypesAndCodes','LocalAppPackageId','LocalUserOwner','LocalUserAuthorizedList','RemoteUserAuthorizedList','RemoteMachineAuthorizedList')){if($null -eq $d[$k]){$d[$k]=''}};
 $d['Interfaces']=@($r.Interfaces | ForEach-Object {[string]$_});
 return ($d | ConvertTo-Json -Depth 5 -Compress)
};
function Matches($name){
 $rules=$p.Rules; $count=$rules.Count; $seen=0; $found=@();
 if($count -gt 16384){throw 'enumeration bound'};
 foreach($r in $rules){$seen++; if($seen -gt 16384){throw 'enumeration bound'}; if([string]::Equals($r.Name,$name,[StringComparison]::OrdinalIgnoreCase)){$found+=$r}};
 if($seen -ne $count -or $rules.Count -ne $count){throw 'enumeration changed'};
 return $found
};
function PrefixCount{ return @($p.Rules | Where-Object {$_.Name -like 'NetSentinel:NS102-metadata-spike:*'}).Count };
function Hash($text){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}};
function Inventory{
 $rules=$p.Rules; $count=$rules.Count; $rows=@();
 if($count -gt 16384){throw 'inventory bound'};
 foreach($r in $rules){if($rows.Count -ge 16384){throw 'inventory bound'}; $rows+=(Snap $r)};
 if($rows.Count -ne $count -or $rules.Count -ne $count){throw 'inventory changed'};
 return (Hash (($rows | Sort-Object) -join [char]10))
};
function Policy{ return ((Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy) | ConvertTo-Json -Compress) };
function Save{ $s | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file -Encoding UTF8 };
function NewRule{
 $r=New-Object -ComObject HNetCfg.FWRule;
 $r.Protocol=6; $r.Name=$s.name; $r.Description=$s.marker; $r.ApplicationName=$s.fixture;
 $r.RemoteAddresses='8.8.8.8'; $r.RemotePorts='443'; $r.LocalAddresses='*'; $r.LocalPorts='*';
 $r.Profiles=2; $r.Direction=2; $r.Action=0; $r.Enabled=$false;
 $r.InterfaceTypes='All'; $r.EdgeTraversal=$false; $r.EdgeTraversalOptions=0;
 return $r
};
"""

PREPARE = r"""
if(Test-Path -LiteralPath $file){throw 'receipt must be new'};
if((PrefixCount) -ne 0){throw 'stale probe rule'};
$id=[guid]::NewGuid().ToString('D'); $bytes=New-Object byte[] 32;
$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($bytes)}finally{$rng.Dispose()};
$witness=([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant();
$s=[pscustomobject][ordered]@{
 stage='PREPARED'; name=('NetSentinel:NS102-metadata-spike:'+$id); identity=$id;
 witness=$witness; marker=('NetSentinel response witness v1 '+$id+' '+$witness);
 fixture=(Join-Path $env:TEMP ('NetSentinel-NS102-metadata-fixture-'+$id+'.exe'));
 before_count=$p.Rules.Count; before_hash=(Inventory); before_policy=(Policy);
 effective_policy=(Get-ExecutionPolicy).ToString();
 build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;
 ubr=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR;
 expected=''; drift=''; cleanup='not_needed'
};
if(Test-Path -LiteralPath $s.fixture){throw 'unexpected fixture exists'};
$r=NewRule; $s.expected=Snap $r;
if(@(Matches $s.name).Count -ne 0){throw 'identity collision'};
Save;
[pscustomobject]@{status=$s.stage; build=$s.build; ubr=$s.ubr; rule_count=$s.before_count; stale_count=(PrefixCount); policy=$s.effective_policy; name=$s.name; witness=$s.witness; marker_length=$s.marker.Length; inventory_hash=$s.before_hash} | ConvertTo-Json -Compress
"""

CREATE = r"""
$s=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json;
if($s.stage -cne 'PREPARED'){throw 'never replay Add from an uncertain stage'};
if(@(Matches $s.name).Count -ne 0 -or (PrefixCount) -ne 0){throw 'collision; no Add'};
if((Inventory) -cne $s.before_hash -or (Policy) -cne $s.before_policy){throw 'baseline changed'};
$r=NewRule; if((Snap $r) -cne $s.expected){throw 'detached full state mismatch'};
$s.stage='ATTEMPT'; $s.cleanup='unknown_add_outcome'; Save;
if(@(Matches $s.name).Count -ne 0){throw 'final boundary collision; no Add'};
$p.Rules.Add($r);
$s.stage='ADDED'; $s.cleanup='pending'; Save;
$fresh=@(Matches $s.name);
if($fresh.Count -ne 1 -or (Snap $fresh[0]) -cne $s.expected){throw 'full readback mismatch'};
$s.stage='VERIFIED'; Save;
[pscustomobject]@{status=$s.stage; count=$p.Rules.Count; unique=$fresh.Count; full_equality=$true; collision_preflight_absent=$true; existing_identity_would_refuse=(@(Matches $s.name).Count -ne 0); add_attempts=1; enabled=$fresh[0].Enabled} | ConvertTo-Json -Compress
"""

READ = r"""
$s=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json;
$fresh=@(Matches $s.name); if($fresh.Count -ne 1){throw 'fresh unique identity required'};
$r=$fresh[0]; $exact=[string]::Equals($r.Description,$s.marker,[StringComparison]::Ordinal);
$bytes=[Text.Encoding]::UTF8.GetBytes($r.Description);
$expectedBytes=[Text.Encoding]::UTF8.GetBytes($s.marker);
$byteExact=([BitConverter]::ToString($bytes) -ceq [BitConverter]::ToString($expectedBytes));
$witnessExact=([string]$r.Description -ceq ('NetSentinel response witness v1 '+$s.identity+' '+$s.witness));
$full=((Snap $r) -ceq $s.expected);
if(-not $exact -or -not $byteExact -or -not $witnessExact -or -not $full){throw 'witness/readback mismatch'};
if(-not [string]::Equals($r.Name,$s.name,[StringComparison]::Ordinal)){throw 'name drift'};
[pscustomobject]@{status='READBACK_PASS'; unique=$fresh.Count; name_exact=$true; description_exact=$exact; bytes_exact=$byteExact; witness_exact=$witnessExact; marker_characters=$r.Description.Length; marker_utf8_bytes=$bytes.Length; full_equality=$full; truncation=$false; transformation=$false} | ConvertTo-Json -Compress
"""

DRIFT = r"""
$s=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json;
if($s.stage -cne 'VERIFIED'){throw 'drift only after verified originating Add'};
$fresh=@(Matches $s.name); if($fresh.Count -ne 1 -or (Snap $fresh[0]) -cne $s.expected){throw 'pre-drift equality required'};
$changed=$s.expected | ConvertFrom-Json; $changed.Description=$s.marker+' changed';
$s.drift=$changed | ConvertTo-Json -Depth 5 -Compress;
$s.stage='DRIFT_ATTEMPT'; Save;
$fresh[0].Description=$changed.Description;
$fresh=@(Matches $s.name);
if($fresh.Count -ne 1 -or (Snap $fresh[0]) -cne $s.drift){throw 'unexpected post-edit state'};
if((Snap $fresh[0]) -ceq $s.expected -or $fresh[0].Description -ceq $s.marker){throw 'original witness unexpectedly still equal'};
$s.stage='DRIFT_VERIFIED'; Save;
[pscustomobject]@{status=$s.stage; description_change_observable=$true; original_description_equal=$false; original_witness_equal=$false; all_other_fields_equal=$true; production_classification='externally_modified'; production_remove_authority=$false} | ConvertTo-Json -Compress
"""

CLEANUP = r"""
$s=Get-Content -LiteralPath $file -Raw | ConvertFrom-Json;
$fresh=@(Matches $s.name);
if($fresh.Count -gt 1){throw 'cleanup refuses ambiguity'};
$removed=$false;
if($fresh.Count -eq 1){
 $observed=Snap $fresh[0];
 if($observed -cne $s.expected -and ($s.drift -ceq '' -or $observed -cne $s.drift)){throw 'cleanup refuses unexpected full state'};
 $p.Rules.Remove($s.name); $removed=$true
};
if(@(Matches $s.name).Count -ne 0 -or (PrefixCount) -ne 0){throw 'stale probe rule after cleanup'};
$afterHash=Inventory; $afterPolicy=Policy;
$same=($afterHash -ceq $s.before_hash -and $p.Rules.Count -eq $s.before_count);
$policySame=($afterPolicy -ceq $s.before_policy -and (Get-ExecutionPolicy).ToString() -ceq $s.effective_policy);
$s.stage='CLEANED'; $s.cleanup='verified_absent'; Save;
[pscustomobject]@{status=$s.stage; removed=$removed; absence_verified=$true; stale_count=(PrefixCount); before_count=$s.before_count; after_count=$p.Rules.Count; inventory_hash=$afterHash; inventory_equal=$same; execution_policy_unchanged=$policySame; policy=(Get-ExecutionPolicy).ToString()} | ConvertTo-Json -Compress;
if(-not $same -or -not $policySame){throw 'baseline consistency failed'}
"""


def commands(state_path: str) -> dict[str, str]:
    if re.fullmatch(r"C:\\Users\\deneme\\AppData\\Local\\Temp\\NS102-native-[0-9a-f]{32}\.json", state_path) is None:
        raise ValueError("fresh exact dedicated-guest JSON receipt path required")
    result = {}
    for name, body in {"prepare": PREPARE, "create": CREATE, "read": READ,
                       "drift": DRIFT, "cleanup": CLEANUP}.items():
        script = COMMON + f"$file='{state_path}';" + body
        script = " ".join(line.strip() for line in script.splitlines())
        if '"' in script or len(script) > 7000:
            raise ValueError("inline command exceeds reviewed transport constraints")
        result[name] = f'powershell -NoProfile -NonInteractive -Command "{script}"'
    return result
