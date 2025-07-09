using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using GlavneMetode.Helpers;
using GlavneMetode.RSA;

namespace Client
{
    internal class Client
    {
        static void Main(string[] args)
        {
            byte[] buffer = new byte[4096];
            Console.WriteLine("[INFO] Unesite IP adresu servera:");
            string ipInput = Console.ReadLine();
            if (!IPAddress.TryParse(ipInput, out IPAddress ipAddress))
            {
                Console.WriteLine("[GRESKA] Neispravna IP adresa!");
                return;
            }

            Console.WriteLine("[INFO] Unesite port servera:");
            if (!int.TryParse(Console.ReadLine(), out int port) || port < 1 || port > 65535)
            {
                Console.WriteLine("[GRESKA] Port mora biti broj izmedju 1 i 65535!");
                return;
            }

            Console.WriteLine("[INFO] Odaberite protokol:\n1 - TCP\n2 - UDP");
            if (!int.TryParse(Console.ReadLine(), out int protokol) || (protokol != 1 && protokol != 2))
            {
                Console.WriteLine("[GRESKA] Protokol mora biti 1 ili 2!");
                return;
            }

            Console.WriteLine("[INFO] Odaberite sifrovanje:\n1 - 3DES\n2 - AES");
            if (!int.TryParse(Console.ReadLine(), out int sifra) || (sifra != 1 && sifra != 2))
            {
                Console.WriteLine("[GRESKA] Sifrovanje mora biti 1 ili 2!");
                return;
            }

            byte[] keySymmetric = sifra == 1 ? new byte[24] : new byte[32];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(keySymmetric);
            }

            Console.WriteLine("[INFO] Heš ključa: " + SHAHelper.Hash(Convert.ToBase64String(keySymmetric)));

            UdpClient udpClient = new UdpClient(0); // koristimo isti socket sve vreme
            udpClient.Connect(ipAddress, 27015);

            string initMsg = protokol + " " + sifra + " " + port;
            byte[] initBytes = Encoding.UTF8.GetBytes(initMsg);
            udpClient.Send(initBytes, initBytes.Length);

            IPEndPoint remoteEP = null;
            byte[] rsaResp = udpClient.Receive(ref remoteEP);
            string serverPublicKey = Encoding.UTF8.GetString(rsaResp);
            Console.WriteLine("[INFO] Primljen javni RSA ključ.");

            byte[] encryptedKey = RSAEncryption.EncryptSymmetricKey(keySymmetric, serverPublicKey);
            udpClient.Send(encryptedKey, encryptedKey.Length);
            Console.WriteLine("[INFO] Simetrični ključ poslat.");

            if (protokol == 1)
            {
                Socket tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcpSocket.Connect(ipAddress, port);
                Console.WriteLine("[INFO] TCP konekcija uspostavljena.");

                while (true)
                {
                    Console.Write("Unesite poruku: ");
                    string msg = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(msg)) continue;

                    string hash = SHAHelper.Hash(msg);
                    string combined = msg + "|" + hash;
                    byte[] encrypted = sifra == 1 ? TripleDES.Encrypt3DES(combined, keySymmetric) : AES.Encrypt(combined, keySymmetric);

                    tcpSocket.Send(encrypted);
                    if (msg.ToLower() == "kraj") break;

                    int len = tcpSocket.Receive(buffer);
                    byte[] receivedData = new byte[len];
                    Array.Copy(buffer, receivedData, len);

                    string response = sifra == 1
                        ? TripleDES.Decrypt3DES(receivedData, keySymmetric)
                        : AES.Decrypt(receivedData, keySymmetric);
                    PrintResponse(response);
                }

                tcpSocket.Close();
            }
            else // UDP
            {
                udpClient = new UdpClient();
                udpClient.Connect(ipAddress, port);
                IPEndPoint serverUdpEP = null;

                while (true)
                {
                    Console.Write("Unesite poruku: ");
                    string msg = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(msg)) continue;

                    string hash = SHAHelper.Hash(msg);
                    string combined = msg + "|" + hash;
                    byte[] encrypted = sifra == 1 ? TripleDES.Encrypt3DES(combined, keySymmetric) : AES.Encrypt(combined, keySymmetric);

                    udpClient.Send(encrypted, encrypted.Length);
                    if (msg.ToLower() == "kraj") break;

                    byte[] responseBytes = udpClient.Receive(ref serverUdpEP);
                    string response = sifra == 1 ? TripleDES.Decrypt3DES(responseBytes, keySymmetric) : AES.Decrypt(responseBytes, keySymmetric);
                    PrintResponse(response);
                }

                udpClient.Close();
            }

            Console.WriteLine("[INFO] Klijent zavrsio.");
        }

        static void PrintResponse(string response)
        {
            string[] parts = response.Split('|');
            if (parts.Length == 2)
            {
                string text = parts[0];
                string hash = parts[1];
                if (SHAHelper.Hash(text) == hash)
                    Console.WriteLine("[INTEGRITET OK] Odgovor: " + text);
                else
                    Console.WriteLine("[INTEGRITET NIJE OK] Odgovor: " + text);
            }
            else
            {
                Console.WriteLine("Odgovor: " + response);
            }
        }
    }
}