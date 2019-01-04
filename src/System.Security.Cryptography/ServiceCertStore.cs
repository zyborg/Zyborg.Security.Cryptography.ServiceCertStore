using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography
{
    public static class ServiceCertStore
    {
        // These constants borrowed from:
        //  https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.X509Certificates/src/System/Security/Cryptography/X509Certificates/X509Store.cs#L13
        internal const string RootStoreName = "Root";
        internal const string IntermediateCAStoreName = "CA";
        internal const string DisallowedStoreName = "Disallowed";

        public static X509Store OpenStore(string serviceName, StoreName storeName = StoreName.My)
        {
            // Based on [this](https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.X509Certificates/src/System/Security/Cryptography/X509Certificates/X509Store.cs#L44)
            // we map the StoreName enum to a literal string value:

            // Default to the enum value name
            var storeNameValue = Enum.GetName(typeof(StoreName), storeName);
            // There are a few cases that don't follow that convention
            switch (storeName)
            {
                case StoreName.CertificateAuthority:
                    storeNameValue = IntermediateCAStoreName;
                    break;
                case StoreName.Disallowed:
                    storeNameValue = DisallowedStoreName;
                    break;
                case StoreName.Root:
                    storeNameValue = RootStoreName;
                    break;
            }

            return OpenStore(serviceName, storeNameValue);
        }

        public static X509Store OpenStore(string serviceName, string storeName)
        {
            var storeHandle = CertOpenStoreStringPara(
                13           // CERT_STORE_PROV_SYSTEM_REGISTRY_W
                ,0           // No encoding type for registry stores
                ,IntPtr.Zero // NULL for the crypto provider implies default
                ,(5 << 16)   // CERT_SYSTEM_STORE_SERVICES_ID for Upper Word
                , $"{serviceName}\\{storeName}");

            if (storeHandle == IntPtr.Zero)
            {
                var lastErr = Marshal.GetLastWin32Error();
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // At this point we have a good handle to the cert store, so if there
            // is any issue wrapping that with a managed object, we want to be
            // sure to clean up the handle before trickling up any exception
            try
            {
                return new X509Store(storeHandle);
            }
            catch
            {
                CertCloseStore(storeHandle, 0);
                throw;
            }
        }


        // From:  https://www.pinvoke.net/default.aspx/crypt32.certopenstore
        [DllImport("CRYPT32.DLL", EntryPoint = "CertOpenStore", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenStoreStringPara(int storeProvider, int encodingType,
            IntPtr hcryptProv, int flags, String pvPara);

        // From:  https://www.pinvoke.net/default.aspx/crypt32.CertCloseStore
        [DllImport("CRYPT32.DLL", EntryPoint = "CertCloseStore", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertCloseStore(IntPtr storeProvider, int flags);
    }
}