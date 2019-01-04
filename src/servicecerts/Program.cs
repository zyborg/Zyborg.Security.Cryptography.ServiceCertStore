using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Zyborg.Security.Cryptography;

namespace servicecerts
{
    [Subcommand(
        typeof(ListCerts),
        typeof(ImportCert),
        typeof(RemoveCert))]
    class Program
    {
        public static Program LastInstance { get; private set; }

        public static readonly StoreName DefaultStore =
            System.Security.Cryptography.X509Certificates.StoreName.My;

        public Program() => LastInstance = this;

        static async Task<int> Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        [Option("--list-stores",
            "List available pre-defined Certificate Store names",
            CommandOptionType.NoValue)]
        public bool ListStores { get; }

        [Option("-s|--service",
            "The service name",
            CommandOptionType.SingleValue)]
        public string ServiceName { get; }

        [Option("-t|--store",
            "The store name",
            CommandOptionType.SingleValue)]
        public StoreName StoreName { get; } = DefaultStore;

        private int OnExecute(CommandLineApplication app)
        {
            if (ListStores)
            {
                app.Out.WriteLine("Pre-defined Certificate Store names:");
                foreach (var s in Enum.GetNames(typeof(StoreName)))
                {
                    app.Out.WriteLine($"  {s}");
                }
                return 0;
            }

            app.Error.WriteLine("You must specify an option or a subcommand.");
            app.ShowHelp();
            return 1;
        }

        public string ServiceStoreName => $"{ServiceName}\\{StoreName}";

        public X509Store OpenStore()
        {
            if (string.IsNullOrEmpty(ServiceName))
                throw new ArgumentException("missing required service name argument");

            return ServiceCertStore.OpenStore(ServiceName, StoreName);
        }

        [Command("list", Description = "List current certificates")]
        public class ListCerts
        {
            private int OnExecute(CommandLineApplication app)
            {
                var parent = Program.LastInstance;
                try
                {
                    using (var store = parent.OpenStore())
                    {
                        app.Out.WriteLine($"Existing certificates under [{parent.ServiceStoreName}]:");
                        if (store.Certificates.Count == 0)
                        {
                            app.Out.WriteLine("  (none)");
                        }
                        else
                        {
                            app.Out.WriteLine(" FriendlyName | Subject | Issuer | Thumbprint | NotBefore | NotAfter | HasPrivateKey");
                            app.Out.WriteLine("==============|=========|========|============|===========|==========|===============");
                            foreach (var c in store.Certificates)
                            {
                                app.Out.WriteLine($" {c.FriendlyName} | {c.Subject} | {c.Issuer} | {c.Thumbprint} | {c.NotBefore} | { c.NotAfter} | {c.HasPrivateKey}");
                            }
                        }

                        store.Close();
                    }

                    return 0;
                }
                catch (ArgumentException ex)
                {
                    app.Error.WriteLine(ex.Message);
                    app.ShowHelp();
                    return -1;
                }
            }
        }

        [Command("import", Description = "Import a certificate from file")]
        public class ImportCert
        {
            [Required]
            [Argument(0, "file",
                "The path to a certificate file to import into the service-specific store")]
            public string File { get; }

            private int OnExecute(CommandLineApplication app)
            {
                var parent = Program.LastInstance;
                var cert = new X509Certificate2(File);

                try
                {
                    using (var store = parent.OpenStore())
                    {
                        store.Add(cert);
                        app.Out.WriteLine($"Certificate imported under [{parent.ServiceStoreName}]:");

                        store.Close();
                    }

                    return 0;
                }
                catch (ArgumentException ex)
                {
                    app.Error.WriteLine(ex.Message);
                    app.ShowHelp();
                    return -1;
                }
            }
        }

        [Command("remove", Description = "Import a certificate from file")]
        public class RemoveCert
        {
            [Required]
            [Argument(0, "thumbprint",
                "The thumbprint of the certificate to remove")]
            public string Thumbprint { get; }

            private int OnExecute(CommandLineApplication app)
            {
                var parent = Program.LastInstance;

                try
                {
                    using (var store = parent.OpenStore())
                    {
                        var certs = store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, false);

                        if (certs.Count == 0)
                        {
                            app.Out.WriteLine($"No certificates matching Thumbprint found under [{parent.ServiceStoreName}]");
                            return 1;
                        }

                        store.Remove(certs[0]);
                        app.Out.WriteLine($"Certificate removed under [{parent.ServiceStoreName}]");

                        store.Close();
                    }

                    return 0;
                }
                catch (ArgumentException ex)
                {
                    app.Error.WriteLine(ex.Message);
                    app.ShowHelp();
                    return -1;
                }
            }
        }
    }
}
