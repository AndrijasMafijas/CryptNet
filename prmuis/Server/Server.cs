using GlavneMetode;
using GlavneMetode.Helpers;
using GlavneMetode.Models;
using GlavneMetode.RSA;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Server
{
    public class Server
    {

        public static Dictionary<string, (string clientPublicKey, string serverPublicKey, string serverPrivateKey)> udpClientKeys =
            new Dictionary<string, (string clientPublicKey, string serverPublicKey, string serverPrivateKey)>();

        public static Dictionary<string, NacinKomunikacije> komunikacijePoHesu =
            new Dictionary<string, NacinKomunikacije>();

        static void Main(string[] args)
        {
            byte[] buffer = new byte[4096];

            Console.WriteLine("[INFO] Čekam početni signal klijenta sa informacijama (UDP paket sa protokolom, algoritmom, portom i ključem)");

            UdpClient udpListener = new UdpClient(27015);
            IPEndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);

            RSAEncryption.GenerateKeys(out string serverPublicKey, out string serverPrivateKey);

            var initResult = udpListener.Receive(ref remoteEP);
            string initMessage = Encoding.UTF8.GetString(initResult);
            Console.WriteLine($"[INFO] Primljeno od {remoteEP}: {initMessage}");

            var parts = initMessage.Split(' ');
            if (parts.Length != 3)
            {
                Console.WriteLine("[GRESKA] Neispravan inicijalni paket (ocekujem 3 dela: protokol, algoritam, port)");
                return;
            }

            int protocol = int.Parse(parts[0]); // 1 = TCP, 2 = UDP
            int algorithm = int.Parse(parts[1]); // 1 = 3DES, 2 = AES
            int clientPort = int.Parse(parts[2]);


            string encryptionAlgo = algorithm == 1 ? "3DES" : "AES";
            string hashedAlgorithm = SHAHelper.Hash(encryptionAlgo);
            Console.WriteLine($"[INFO] Heš algoritma ({encryptionAlgo}): {hashedAlgorithm}");
            Console.WriteLine($"[INFO] Klijent je odabrao protokol {(protocol == 1 ? "TCP" : "UDP")} i algoritam {encryptionAlgo}");

            // Pošalji serverov javni RSA ključ klijentu
            byte[] serverKeyBytes = Encoding.UTF8.GetBytes(serverPublicKey);
            udpListener.Send(serverKeyBytes, serverKeyBytes.Length, remoteEP);
            Console.WriteLine("[INFO] Poslat javni RSA ključ klijentu.");

            // Primi šifrovani simetrični ključ
            byte[] encryptedKey = udpListener.Receive(ref remoteEP);
            byte[] keyBytes;

            try
            {
                keyBytes = RSAEncryption.DecryptSymmetricKey(encryptedKey, serverPrivateKey);
                Console.WriteLine("[INFO] Simetrični ključ uspešno dešifrovan.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[GRESKA] Dešifrovanje ključa nije uspelo: " + ex.Message);
                return;
            }

            if (algorithm == 2) // AES
            {
                if (keyBytes.Length != 32)
                {
                    Console.WriteLine("[GRESKA] AES ključ mora biti 32 bajta dug (256-bit).");
                    return;
                }

                if (protocol == 1)
                {
                    var komunikacija = new NacinKomunikacije(protocol, encryptionAlgo, Convert.ToBase64String(keyBytes), remoteEP)
                    {
                        HesiraniNazivAlgoritma = hashedAlgorithm
                    };
                    komunikacijePoHesu[hashedAlgorithm] = komunikacija;

                    StartTcpAes.StartTCPServerAES(clientPort, keyBytes);
                }
                else
                {
                    string clientId = remoteEP.Address.ToString();
                    // Čuvamo AES ključ kao Base64 string (možeš i byte[], ali Base64 je lakše za debug)
                    udpClientKeys[clientId] = (Convert.ToBase64String(keyBytes), "", "");
                    Console.WriteLine($"[INFO] Zapamćen AES ključ za UDP klijenta {clientId}");

                    var komunikacija = new NacinKomunikacije(protocol, encryptionAlgo, Convert.ToBase64String(keyBytes), remoteEP)
                    {
                        HesiraniNazivAlgoritma = hashedAlgorithm
                    };
                    komunikacijePoHesu[hashedAlgorithm] = komunikacija;

                    StartUdpAes.StartUDPServerAES(clientPort);
                }
            }
            else // 3DES
            {
                string clientId = remoteEP.Address.ToString();
                udpClientKeys[clientId] = (Convert.ToBase64String(keyBytes), "", "");
                Console.WriteLine($"[INFO] Zapamćen 3DES ključ za UDP klijenta {clientId}");

                if (protocol == 1)
                {
                    var komunikacija = new NacinKomunikacije(protocol, encryptionAlgo, Convert.ToBase64String(keyBytes), remoteEP)
                    {
                        HesiraniNazivAlgoritma = hashedAlgorithm
                    };
                    komunikacijePoHesu[hashedAlgorithm] = komunikacija;
                    StartTcp3Des.StartTCPServer3DES(clientPort, keyBytes);
                }
                else
                {
                    var komunikacija = new NacinKomunikacije(protocol, encryptionAlgo, Convert.ToBase64String(keyBytes), remoteEP)
                    {
                        HesiraniNazivAlgoritma = hashedAlgorithm
                    };
                    komunikacijePoHesu[hashedAlgorithm] = komunikacija;
                    StartUdp3Des.StartUDPServer3DES(clientPort);
                }
            }
            PrikazStatistikeRada();
        }
        static void PrikazStatistikeRada()
        {
            Console.WriteLine("\n===== Statistika enkripcije i dekripcije =====");
            Console.WriteLine($"AES - Enkriptovano ukupno: {AESStats.TotalEncryptedBytes} bajtova");
            Console.WriteLine($"AES - Dekriptovano ukupno: {AESStats.TotalDecryptedBytes} bajtova");
            Console.WriteLine($"3DES - Enkriptovano ukupno: {TripleDESStats.TotalEncryptedBytes} bajtova");
            Console.WriteLine($"3DES - Dekriptovano ukupno: {TripleDESStats.TotalDecryptedBytes} bajtova");
        }
    }
}
