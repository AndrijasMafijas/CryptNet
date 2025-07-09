using GlavneMetode.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class StartUdpAes
    {
        public static void StartUDPServerAES(int port)
        {
            Console.WriteLine($"[INFO] UDP Server sa AES na portu {port}...");
            UdpClient udpServer = new UdpClient(port);

            bool running = true;

            while (running)
            {
                IPEndPoint clientEP = new IPEndPoint(IPAddress.Any, 0);
                byte[] data = null;

                try
                {
                    data = udpServer.Receive(ref clientEP);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("[GRESKA] Greška pri primanju UDP poruke: " + ex.Message);
                    continue;
                }

                string clientId = clientEP.Address.ToString();
                if (!Server.udpClientKeys.ContainsKey(clientId))
                {
                    Console.WriteLine($"[GRESKA] Nepoznat klijent {clientId}, odbacujem poruku.");
                    continue;
                }

                string hashedAlgo = SHAHelper.Hash("AES");

                if (!Server.komunikacijePoHesu.TryGetValue(hashedAlgo, out var komunikacija))
                {
                    Console.WriteLine("[GRESKA] Nema informacija o algoritmu AES (heš nije nađen).");
                    continue;
                }

                byte[] aesKey = Convert.FromBase64String(Server.udpClientKeys[clientId].clientPublicKey);

                string decryptedMsg;
                try
                {
                    decryptedMsg = AES.Decrypt(data, aesKey);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] AES dekriptovanje poruke neuspelo: " + e.Message);
                    continue;
                }

                Console.WriteLine($"[PRIMLJENO od {clientId}] {decryptedMsg}");

                if (decryptedMsg.Contains("kraj"))
                {
                    Console.WriteLine("[INFO] Primljena komanda 'kraj', server se zatvara...");
                    running = false;
                    break;
                }

                Console.Write("Unesite odgovor za UDP klijenta: ");
                string odgovor = Console.ReadLine();

                byte[] encryptedResponse;
                try
                {
                    encryptedResponse = AES.Encrypt(odgovor, aesKey);
                    udpServer.Send(encryptedResponse, encryptedResponse.Length, clientEP);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[GRESKA] AES šifrovanje odgovora neuspelo: " + e.Message);
                }

                if (odgovor.ToLower() == "kraj")
                {
                    Console.WriteLine("[INFO] Server se zatvara po komandi sa servera.");
                    running = false;
                    break;
                }
            }

            udpServer.Close();
            Console.WriteLine("[INFO] UDP Server zatvoren.");
        }
    }
}
