namespace Sample.SmartCard
{
    using System;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    internal class Program
    {
        public static NameValueCollection Parse(X500DistinguishedName name)
        {
            var result = new NameValueCollection();

            if (name?.Name != null)
            {
                foreach (var field in name.Name.Split(','))
                {
                    var parts = field.Split('=', 2);

                    if (parts.Length == 2)
                    {
                        result.Add(parts[0].Trim(), parts[1].Trim());
                    }
                }
            }

            return result;
        }

        private static void Main(string[] args)
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            foreach (var cert in store.Certificates.Cast<X509Certificate2>()
                .Where(c =>
                    c.HasPrivateKey &&
                    c.Extensions.Cast<X509Extension>().Any(x =>
                        (x.Oid?.Value == "2.5.29.37") &&
                        x is X509EnhancedKeyUsageExtension ekx &&
                        ekx.EnhancedKeyUsages.Cast<Oid>().Any(o =>
                            o.Value == "1.3.6.1.4.1.311.20.2.2"))))
            {
                Console.WriteLine("Subject:       {0}", cert.Subject);
                Console.WriteLine("Issuer:        {0}", cert.Issuer);

                var cn = cert.GetNameInfo(X509NameType.SimpleName, false)?.Split('.');

                if (cn?.Length == 4)
                {
                    Console.WriteLine("EDIPI:         {0}", cn[3]);
                    Console.WriteLine("FirstName:     {0}", cn[1]);
                    Console.WriteLine("MiddleName     {0}", cn[2]);
                    Console.WriteLine("LastName       {0}", cn[0]);
                }

                var subject = Parse(cert.SubjectName);

                foreach (var key in subject.AllKeys)
                {
                    foreach (var value in subject.GetValues(key))
                    {
                        Console.WriteLine("{0,-14} {1}", string.Concat(key, ':'), value);
                    }
                }

                Console.WriteLine("FriendlyName:  {0}", cert.FriendlyName);
                Console.WriteLine("Thumbprint:    {0}", cert.Thumbprint);
                Console.WriteLine("SerialNumber:  {0}", cert.SerialNumber);
                Console.WriteLine("Verified:      {0}", cert.Verify());

                foreach (var extension in cert.Extensions)
                {
                    Console.WriteLine("Extension:     {0} ({1})", extension.Oid?.FriendlyName, extension.Oid?.Value);

                    switch (extension.Oid?.Value)
                    {
                        case "2.5.29.15" when extension is X509KeyUsageExtension kuex:
                        {
                            Console.WriteLine("Usages:        {0}", kuex.KeyUsages);
                            break;
                        }

                        case "2.5.29.37" when extension is X509EnhancedKeyUsageExtension ekux:
                        {
                            foreach (var usage in ekux.EnhancedKeyUsages)
                            {
                                Console.WriteLine("Usage:         {0} ({1})", usage.FriendlyName, usage.Value);
                            }

                            break;
                        }
                    }
                }

                ////using var chain = new X509Chain();
                ////chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                ////chain.Build(cert);
                ////chain.Reset();

                ////using var rsa = cert.GetRSAPrivateKey();
                ////var data = Encoding.UTF8.GetBytes("Virtual Training Suite");
                ////rsa?.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                ////X509Certificate2UI.DisplayCertificate(cert);

                Console.WriteLine();
            }

            Console.Write("Press any key to exit...");
            Console.ReadKey(true);
            Console.WriteLine();
        }
    }
}