<# This could do with being placed in the module and a control script written to call it but will have to wait until we have more white space. 

1. Find the VNG 
2. Configure the address space
3. Create the root certificate and import it
4. Export the public portion of the root certificate
5. Export the public \ private key pfx of root certificate (password protected)
6. Upload the public portion to the VNG configuration with the name set the same as the certificate name exported (so you can track them)
6. Create the client certificates 
7. Export the client certificates 
8. Download the VPN client from the VNG
9. Extract the VPN client software
10. Begin install of VPN software package.

 Change the prefix and exportpath as you wish. Change password as you wish, later this should ask for a password and we should manage where these passwords are stored. 
 Other future improvements include: 

 It should detect if this process has been run before, otherwise things get messy with multiple certs installed and exported. 
 It should prompt useful information not just output from the cmdlet runs to make it more informative to the user #>
 
do {
    $prefix = Read-Host "Please provide a three character prefix to use for the certificates and certificate data" 

} while ($prefix -notmatch [regex]'^[A-Z0-9a-z]{3}$')

If ($prefix)
{
    $prefix = (($prefix | select -First 1  | select -expandproperty ResourceGroupName).split("-")[-1]).substring(0,3)
    $allok = read-host "Customer code '$prefix' found, use this as prefix for cert creation? (y\n) "
    If (-not ($allok -match 'yes|y'))
    {
        write-host "Aborting" -ForegroundColor Red
        break
    }
}   
    while ($null -eq $prefix) 
    {
        $prefix = read-host "Could not determine customer code from resource group name. Please specify a three digit alphanumeric prefix to use for certificate creation and export folder creation"
        if (-not($prefix -match '^\w{3}$')) 
        {
            $prefix = $null
            write-host "That was not a three digit alphanumeric prefix" -ForegroundColor Red
        }
    }


$numclientcerts = $null
while ($numclientcerts -notmatch '\b([1-9]|[1-8][0-9]|9[0-9]|1[01][0-9]|12[0-8])\b') 
    {
       
        $numClientcerts = read-host "How many certs would you like, it's 1 by default [Enter for 1 or specify alternative 1-128]? "
        If ($numclientcerts -eq $null) {$numClientcerts = 1}
        
        if (($numclientcerts -notmatch '\b([1-9]|[1-8][0-9]|9[0-9]|1[01][0-9]|12[0-8])\b') -and ($numclientcerts -notmatch $null))
        {
            write-host "That was not a value 1-128" -ForegroundColor Red
        }
    }

$exportpath           = "C:\temp\$($prefix)AzureP2S"
$exportpwd            = ConvertTo-SecureString -String "Azur3C3rt1" -Force -AsPlainText
$caname               = "$($prefix)P2SRoot"
$VPNClientAddressPool = "192.168.67.128/25"

if (-not (Test-Path $exportpath)) 
{
    New-Item $exportpath -ItemType Directory
}else
{
    $deleteold = read-host "There is an existing directory called $exportpath, happy to remove this and all old data in it (y\n)?"
    if ($deleteold -match 'yes|y')
    {
        Remove-Item $exportpath -Recurse -Force
    }else
    {
        write-host "Aborting" -ForegroundColor red
        break
    }
}

if (-not (Test-Path "$exportpath\VPNClient")) 
{
    New-Item $exportpath\VPNClient -ItemType Directory
}

if (-not (Test-Path "$exportpath\ClientCerts")) 
{
    New-Item $exportpath\ClientCerts -ItemType Directory
}

if (-not (Test-Path "$exportpath\RootCert")) 
{
    New-Item $exportpath\RootCert -ItemType Directory
}

# Will create 2 yr root cert 
$certproperties = @{

    Type = "Custom"
    Keyspec = "Signature"
    Subject = "CN=$($caname)"
    KeyExportPolicy = "Exportable"
    HashAlgorithm = "sha256" 
    KeyLength = "2048"
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyUsageProperty = "Sign" 
    KeyUsage = "CertSign"
    NotAfter = (get-date).AddYears(2)
}

$cert = New-SelfSignedCertificate  @certproperties 

Export-Certificate -Cert $cert -FilePath "$($exportpath)\RootCert\$($caname)-tmp.cer" -NoClobber                         # This is the public certificate encoded     
certutil -encode "$($exportpath)\RootCert\$($caname)-tmp.cer" "$($exportpath)\RootCert\$($caname)_PublicCert.cer"        # This is the public certificate to import into Azure P2S config.
Remove-Item "$($exportpath)\RootCert\$($caname)-tmp.cer" -Force

# Add P2S creation on Azure site plus add the public key data in there 

Export-pfxCertificate -Cert $cert -FilePath "$($exportpath)\RootCert\$($caname)-withPrivateKey.pfx" -NoClobber -Password $exportpwd # This is an export of Public \ Private password protected pfx to generate further certificate
$PublicKeyValue = [System.Convert]::ToBase64String($cert.GetRawCertData()) # To add to Azure

foreach($i in 1..$numclientcerts)
{
    $clientcertname = "$($prefix)P2SClient$($i)" 
    $clientcert = New-SelfSignedCertificate -Type Custom -DnsName P2SChildCert -KeySpec Signature -Subject "CN=$($clientcertname)" -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -NotAfter (get-date).AddYears(2)
    Export-PfxCertificate -cert $clientcert -FilePath "$($exportpath)\ClientCerts\$($clientcertname).pfx" -password $exportpwd # This is the client cert 
}

 

<# There is a bug in Azure which kills the VNGs S2S when removing and then adding a new cert. For this reason, do this step manually and be aware even then you're probably
have to reset the VNG to restore the S2S connections - at time of writing had opened a ticket with MS #>

$VNG = get-azurermresourcegroup | Get-AzureRmVirtualNetworkGateway
If ($VNG)
{
    If ($VNG.count -eq 1)
    {
        $rg      = $vng.ResourceGroupName
        $vngname = $vng.name
    }
    else 
    {
        $VNGselection = ($VNG | select Name,ResourceGroupName | Out-GridView -title "Select VNG" -OutputMode Single)
        If ($vngselection)
        {
            $rg      = $vngselection.ResourceGroupName
            $vngname = $vngselection.name
            $VNG = $VNG | ? {$_.Name -eq $vngname -and $_.ResourceGroupName -eq $rg}
        }
        else 
        {
            Write-host "No VNG selected." -ForegroundColor red
            break
        }
    }
}
else
{
    Write-host "No VNG found in this subscription" -ForegroundColor red
    break
}

$vngok = $null
$vngok = read-host "P2S configuration will happen on $vngname , is this ok [y\n]?"
if ($vngok -notmatch 'yes|y') 
{
    write-host "Aborting" -ForegroundColor Red
    break
}

if (($vng.vpnclientconfiguration.vpnclientaddresspool.addressprefixes -ne $VPNClientAddressPool) -and ($null -ne $vng.vpnclientconfiguration.vpnclientaddresspool.addressprefixes))
{
    $reallydoit = read-host "It appears you are changing the IP address pool from $($vng.vpnclientconfiguration.vpnclientaddresspool.addressprefixes) to $VPNClientAddressPool on $vngname - Are you sure?"
    if ($reallydoit -match 'y|yes')
    {
        Set-AzureRmVirtualNetworkGateway -VirtualNetworkGateway $vng -VpnClientAddressPool $VPNClientAddressPool
    }else
    {
        write-host "Aborting script"
        break
    }
}
else
{
    Set-AzureRmVirtualNetworkGateway -VirtualNetworkGateway $vng -VpnClientAddressPool $VPNClientAddressPool
} 

# https://docs.microsoft.com/en-us/azure/vpn-gateway/scripts/vpn-gateway-sample-point-to-site-certificate-authentication-powershell

$keyexists = $null
$keyexists = Get-AzureRmVpnClientRootCertificate -VirtualNetworkGatewayName $vngname -ResourceGroupName $rg | ? {$_.name -eq "$($caname)_PublicCert.cer"}
if ($keyexists)
{
   $replaceold = read-host "There is an existing cert in $vngname called $($caname)_PublicCert.cer, do you want to overwrite it (all existing connection signed by this root certificate will no longer work) (y\n)? "

   if ($replaceold -match 'yes|y')
   {
    remove-AzureRmVpnClientRootCertificate -VpnClientRootCertificateName "$($caname)_PublicCert.cer" `
     -VirtualNetworkGatewayname $VNGname `
     -ResourceGroupName $rg -PublicCertData $keyexists.PublicCertData

    $p2srootcert = New-AzureRmVpnClientRootCertificate -Name "$($caname)_PublicCert.cer" -PublicCertData $PublicKeyValue
    Add-AzureRmVpnClientRootCertificate -VpnClientRootCertificateName "$($caname)_PublicCert.cer" `
     -VirtualNetworkGatewayname $VNGname `
     -ResourceGroupName $rg -PublicCertData $PublicKeyValue

   }
}
else
{
    $p2srootcert = New-AzureRmVpnClientRootCertificate -Name "$($caname)_PublicCert.cer" -PublicCertData $PublicKeyValue
    Add-AzureRmVpnClientRootCertificate -VpnClientRootCertificateName "$($caname)_PublicCert.cer" `
     -VirtualNetworkGatewayname $VNGname `
     -ResourceGroupName $rg -PublicCertData $PublicKeyValue  
}

 $pfl = New-AzureRmVpnClientConfiguration -ResourceGroupName $rg -Name $vngname -AuthenticationMethod "EapTls"
invoke-webrequest -uri $pfl.VPNProfileSASUrl -outfile "$exportpath\VPNClient\VPNclient.zip"
Expand-Archive "$exportpath\VPNClient\VPNclient.zip" -DestinationPath "$exportpath\VPNClient\"
& $exportpath\VPNClient\WindowsAmd64\VpnClientSetupAmd64.exe #>