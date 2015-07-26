https://unlockpowershell.wordpress.com/2009/11/20/script-remote-dcom-wmi-access-for-a-domain-user/

function get-sid
{
Param (
 $DSIdentity
)
 $ID = new-object System.Security.Principal.NTAccount($DSIdentity)
 return $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
}
$sid = get-sid "Domain\User" #Change This...
$SDDL = "A;;CCWP;;;$sid"
$DCOMSDDL = "A;;CCDCRP;;;$sid"
$computers = "localhost" #Allows Change On Multiple Machines
foreach ($strcomputer in $computers)
{
    $Reg = [WMIClass]"\\$strcomputer\root\default:StdRegProv"
    $DCOM = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
    $security = Get-WmiObject -ComputerName $strcomputer -Namespace root/cimv2 -Class __SystemSecurity
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    $binarySD = @($null)
    $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
    $outsddl = $converter.BinarySDToSDDL($binarySD[0])
    $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
    $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
    $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
    $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
    $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
    $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
    $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD
    $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
    $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)
}

netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
