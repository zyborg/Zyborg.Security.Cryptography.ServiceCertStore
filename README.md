# Zyborg.Security.Cryptography.ServiceCertStore
Extension to the .NET X509Store to access Win Service-specific certificate stores

***:star: I appreciate your star, it helps me decide to which OSS projects I should allocate my spare time.***
---

[![Nuget Library](https://img.shields.io/nuget/v/Zyborg.Security.Cryptography.ServiceCertStore.svg)](https://www.nuget.org/packages/Zyborg.Security.Cryptography.ServiceCertStore/)

[![PowerShell Module](https://img.shields.io/powershellgallery/v/ServiceCertStore.svg)](https://www.powershellgallery.com/packages/ServiceCertStore)

---

Use this extension to the BCL `X509Store` class to support access to
Windows Service-specific certificate stores.  See [this blog](https://blog.bkkr.us/service-specific-certificate-store/) for the nitty gritty details.

By default the `X509Store` class only allows access to the stores defined
in the `StoreLocation` enumeration, which is limited to either the
`CurrentUser` or the `LocalMachine`.

But installed Windows Services may have their own instance of a Certificate
Store as well, and there are certain scenarios where accessing this store
is useful or exposes additional functionality.  One concrete example would
be the ability for the NTDS Windows Service to automatically detect and
select updated certificates in its personal store to be used for securing
the LDAPS endpoint, available since Windows 2008 (see the end of
[this article](https://support.microsoft.com/en-us/help/321051/how-to-enable-ldap-over-ssl-with-a-third-party-certification-authority)).

This extension allows you to target a specific named certificate stored
under the context of a Windows Service.  Example usage:

```csharp

public void EnumerateNtdsCerts()
{
    using (var store = ServiceCertStore.OpenStore("NTDS", StoreName.My))
    {
        foreach (var c in store.Certificates)
        {
            Console.WriteLine($"{c.Thumbprint} : {c.Subject}");
        }
    }
}
```
