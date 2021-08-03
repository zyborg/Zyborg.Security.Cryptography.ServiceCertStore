
## Define default display set of properties for our custom service cert object down below
## Ref:  https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
$svcCertDefaultDisplaySet = 'Thumbprint','Subject'
$svcCertDefaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet",[string[]]$svcCertDefaultDisplaySet)
$svcCertPSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($svcCertDefaultDisplayPropertySet)

<#
.DESCRIPTION
Returns a reference to an open service-specific certificate store.
The caller is responsible for closing and disposing of the returned store reference.
#>
function Get-ServiceCertificateStore {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Store])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ServiceName,
        [Parameter(Position = 1)]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName="My"
    )

    return [Zyborg.Security.Cryptography.ServiceCertStore]::OpenStore($ServiceName, $StoreName)
}

<#
.DESCRIPTION
Returns zero or more certificates that are found in a service-specific certificate store.
If you don't specifify any qualifier parameters, then all certificates in the named store
for the named service will be returned.  You can filter this resultset by specifying one
or more qualifier parameters that must be matched on.
#>
function Get-ServiceCertificates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ServiceName,
        [Parameter(Position = 1)]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName="My",

        ## One or more qualifiers to filter the resultset
        [string[]]$Thumbprint,
        [string[]]$Subject
    )

    $store = Get-ServiceCertificateStore $ServiceName $StoreName
    try {
        foreach ($c in $store.Certificates) {
            if ($Thumbprint -and -not ($c.Thumbprint -in $Thumbprint)) {
                continue
            }
            if ($Subject -and -not ($c.Subject -in $Subject)) {
                continue
            }
    
            ## Create a lightweight version of the cert object so
            ## we can dispose of the realy thing before returning
            $svcCert = [pscustomobject]@{
                EnhancedKeyUsageList = $c.EnhancedKeyUsageList
                DnsNameList = $c.DnsNameList
                SendAsTrustedIssuer = $c.SendAsTrustedIssuer
                Archived = $c.Archived
                Extensions = $c.Extensions
                FriendlyName = $c.FriendlyName
                IssuerName = $c.IssuerName
                NotAfter = $c.NotAfter
                NotBefore = $c.NotBefore
                HasPrivateKey = $c.HasPrivateKey
                PrivateKey = $c.PrivateKey
                PublicKey = $c.PublicKey
                RawData = $c.RawData
                SerialNumber = $c.SerialNumber
                SubjectName = $c.SubjectName
                SignatureAlgorithm = $c.SignatureAlgorithm
                Thumbprint = $c.Thumbprint
                Version = $c.Version
                Handle = $c.Handle
                Issuer = $c.Issuer
                Subject = $c.Subject
            }
            $c.Dispose()
            $svcCert | Add-Member MemberSet PSStandardMembers $svcCertPSStandardMembers
            Write-Output $svcCert
        }
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

<#
.DESCRIPTION
Imports a new certificate identified by a file path or a `X509Certificate2` object
instances into a service-specific certificate store.
#>
function Import-ServiceCertificate {
    [CmdletBinding(DefaultParameterSetName="FileImport")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ServiceName,

        [Parameter(Mandatory, ParameterSetName="FileImport", Position = 1)]
        [string]$Path,
        [Parameter(ParameterSetName="FileImport")]
        [securestring]$Password,

        [Parameter(Mandatory, ParameterSetName="CertImport", Position = 1)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName="My"
    )

    if ($Path) {
        $resolvedPath = Resolve-Path $Path
        if ($Password) {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $resolvedPath.Path, $Password)
        }
        else {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $resolvedPath.Path)
        }
    }
    else {
        $cert = $Certificate
    }

    try {
        if (-not $cert.Thumbprint) {
            Write-Error "Could not resolve valid certificate thumbprint"
            return
        }

        $store = Get-ServiceCertificateStore $ServiceName $StoreName
        try {
            $store.Add($cert)
            return $true
        }
        finally {
            $store.Close()
            $store.Dispose()
        }
    }
    finally {
        $cert.Dispose()
    }
}

<#
.DESCRIPTION
Removes a certificate identified by its Thumbprint from a service-specific
certificate store.
#>
function Remove-ServiceCertificate {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ServiceName,
        [Parameter(Mandatory, Position = 1)]
        [string]$Thumbprint,
        [Parameter()]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName="My"

    )

    $store = Get-ServiceCertificateStore $ServiceName $StoreName
    try {
        foreach ($c in $store.Certificates) {
            if ($c.Thumbprint -eq $Thumbprint) {
                $store.Remove($c)
                return $true
            }
        }
    }
    finally {
        $store.Close()
        $store.Dispose()
    }

    return $false
}
