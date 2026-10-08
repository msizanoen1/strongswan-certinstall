using System.Security.Cryptography.X509Certificates;

if (args is not [var filePath])
{
    Console.WriteLine("Usage: strongswan-certinstall <pfx file>");
    return 1;
}

var installBasePath = "/etc/strongswan/ipsec.d";
var installCaPath = "/etc/strongswan/ipsec.d/cacerts";
var installCertPath = "/etc/strongswan/ipsec.d/certs";
var installKeyPath = "/etc/strongswan/ipsec.d/private";

if (!Directory.Exists(installBasePath))
{
    Console.WriteLine("Unsupported distribution");
    return 1;
}

Console.Write("Enter PKCS #12 Password: ");

var password = "";
while (true)
{
    var keyInfo = Console.ReadKey(true);
    if (keyInfo.Key == ConsoleKey.Backspace)
    {
        if (password.Length == 0)
            continue;
        password = password[..^1];
        Console.Write("\b \b");
    }
    else if (keyInfo.Key == ConsoleKey.Enter)
    {
        break;
    }
    else
    {
        password += keyInfo.KeyChar;
        Console.Write("*");
    }
}
Console.WriteLine();

var certificateCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(filePath, password, loaderLimits: Pkcs12LoaderLimits.DangerousNoLimits);

foreach (var caCertificate in certificateCollection.Where(x => !x.HasPrivateKey))
{
    var destinationPath = Path.Join(installCaPath, $"{caCertificate.SubjectName.Name}.pem");
    using (var certFile = File.CreateText(destinationPath))
    {
        certFile.Write(caCertificate.ExportCertificatePem());
    }
    Console.WriteLine($"Installed CA certificate {destinationPath}");
}

foreach (var clientCertificate in certificateCollection.Where(x => x.HasPrivateKey))
{
    var destinationCertPath = Path.Join(installCertPath, $"{clientCertificate.SubjectName.Name}.pem");
    var destinationKeyPath = Path.Join(installKeyPath, $"{clientCertificate.SubjectName.Name}.pem");
    using (var certFile = File.CreateText(destinationCertPath))
    {
        certFile.Write(clientCertificate.ExportCertificatePem());
    }
    Console.WriteLine($"Installed client certificate {destinationCertPath}");
    using (var keyFile = File.CreateText(destinationKeyPath))
    {
        keyFile.Write(GetPrivateKeyPem(clientCertificate));
    }
    Console.WriteLine($"Installed client key {destinationKeyPath}");
}

AddPermissions(installBasePath,
    UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute);

AddPermissions(installCertPath,
    UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

AddPermissions(installKeyPath,
    UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

return 0;

static string GetPrivateKeyPem(X509Certificate2 certificate)
{
    if (certificate.GetRSAPrivateKey() is { } rsaPrivateKey)
    {
        return rsaPrivateKey.ExportPkcs8PrivateKeyPem();
    }
    else if (certificate.GetDSAPrivateKey() is { } dsaPrivateKey)
    {
        return dsaPrivateKey.ExportPkcs8PrivateKeyPem();
    }
    else if (certificate.GetECDsaPrivateKey() is { } ecdsaPrivateKey)
    {
        return ecdsaPrivateKey.ExportPkcs8PrivateKeyPem();
    }
    else if (certificate.GetECDiffieHellmanPrivateKey() is { } ecdhPrivateKey)
    {
        return ecdhPrivateKey.ExportPkcs8PrivateKeyPem();
    }
    throw new NotSupportedException("Unknown private key algorithm");
}

static void AddPermissions(string path, UnixFileMode newPermissions)
{
    File.SetUnixFileMode(path, File.GetUnixFileMode(path) | newPermissions);
}
