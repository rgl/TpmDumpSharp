using System;
using System.Runtime.InteropServices;
using System.Text;
using Tpm2Lib;

namespace TpmDumpKey
{
    class Program
    {
        static void Main(string[] args)
        {
            // see https://github.com/microsoft/TSS.MSR
            // see https://github.com/Azure/azure-iot-sdk-csharp/blob/32166465d4d5d9d4d6dd9a35ad85bd19c38958c0/security/tpm/src/SecurityProviderTpmHsm.cs#L14

            using (var tpmDevice = CreateTpm2Device())
            {
                tpmDevice.Connect();

                using (var tpm = new Tpm2(tpmDevice))
                {
                    DumpEndorsementKey(tpm);
                    DumpStorageRootKey(tpm);
                }
            }
        }

        private static void DumpEndorsementKey(Tpm2 tpm)
        {
            byte[] name;
            byte[] qualifiedName;

            var endorcementKey = tpm.ReadPublic(new TpmHandle(TPM2_EK_HANDLE), out name, out qualifiedName);

            var ek = endorcementKey.GetTpm2BRepresentation();

            Console.WriteLine($"Public Endorcement Key (EK): {ToHexString(ek)}");
        }

        private static void DumpStorageRootKey(Tpm2 tpm)
        {
            byte[] name;
            byte[] qualifiedName;

            var storageRootKey = tpm.ReadPublic(new TpmHandle(TPM2_SRK_HANDLE), out name, out qualifiedName);

            var srk = storageRootKey.GetTpm2BRepresentation();

            Console.WriteLine($"Public Storage Root Key (SRK): {ToHexString(srk)}");
        }

        private const uint TPM2_EK_HANDLE     = ((uint)Ht.Persistent << 24) | 0x00010001;
        private const uint TPM2_SRK_HANDLE    = ((uint)Ht.Persistent << 24) | 0x00000001;

        private static Tpm2Device CreateTpm2Device()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new TbsDevice();
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return new LinuxTpmDevice();
            }

            throw new PlatformNotSupportedException(string.Format("The library doesn't support the current OS platform: {0}", RuntimeInformation.OSDescription));
        }

        private static string ToHexString(byte[] value)
        {
            var hex = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }
}
