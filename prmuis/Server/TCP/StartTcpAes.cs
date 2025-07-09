using GlavneMetode.Helpers;
using GlavneMetode.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class StartTcpAes
    {
        public static void StartTCPServerAES(int port, byte[] firstClientKey)
        {
            Console.WriteLine($"[INFO] TCP Server sa AES na portu {port}...");

            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Any, port));
            listener.Listen(10);
            listener.Blocking = false;

            List<Socket> clients = new List<Socket>();
            Dictionary<Socket, byte[]> clientKeys = new Dictionary<Socket, byte[]>();
            Dictionary<Socket, NacinKomunikacije> clientInfo = new Dictionary<Socket, NacinKomunikacije>();

            Console.WriteLine("[INFO] Server spreman, čeka nove klijente...");

            while (true)
            {
                List<Socket> readList = new List<Socket>(clients) { listener };
                Socket.Select(readList, null, null, 1000000); // timeout = 1 sekunda

                List<Socket> zaUkloniti = new List<Socket>(); // Pomocna lista za zatvaranje konekcija

                foreach (Socket socket in readList)
                {
                    if (socket == listener)
                    {
                        try
                        {
                            Socket newClient = listener.Accept();
                            newClient.Blocking = false;
                            clients.Add(newClient);

                            string hashedAlgo = SHAHelper.Hash("AES");

                            if (Server.komunikacijePoHesu.TryGetValue(hashedAlgo, out var komunikacija))
                            {
                                clientKeys[newClient] = Convert.FromBase64String(komunikacija.Kljuc);
                                clientInfo[newClient] = komunikacija;

                                Console.WriteLine($"[INFO] Novi klijent povezan: {newClient.RemoteEndPoint}, koristi {komunikacija.Algoritam}");
                            }
                            else
                            {
                                Console.WriteLine("[GRESKA] Nema informacije o algoritmu AES (heš nije nađen).");
                                newClient.Close();
                                continue;
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        byte[] buffer = new byte[4096];
                        int received = 0;

                        try
                        {
                            received = socket.Receive(buffer);
                        }
                        catch (SocketException)
                        {
                            Console.WriteLine($"[GRESKA] Socket exception za klijenta {socket.RemoteEndPoint}, uklanjam konekciju.");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        if (received == 0)
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} je prekinuo vezu.");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        byte[] encryptedMsg = new byte[received];
                        Array.Copy(buffer, encryptedMsg, received);

                        string decryptedMsg;
                        try
                        {
                            decryptedMsg = AES.Decrypt(encryptedMsg, clientKeys[socket]);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[GRESKA] Dekripcija neuspešna za {socket.RemoteEndPoint}: {e.Message}");
                            continue;
                        }

                        Console.WriteLine($"[PRIMLJENO od {socket.RemoteEndPoint}] {decryptedMsg} (Algoritam: {clientInfo[socket].Algoritam})");

                        if (decryptedMsg.Contains("kraj"))
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} se diskonektovao komandom 'kraj'.");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        Console.Write($"[ODGOVOR za {socket.RemoteEndPoint}]: ");
                        string odgovor = Console.ReadLine();

                        byte[] encryptedResponse;
                        try
                        {
                            encryptedResponse = AES.Encrypt(odgovor, clientKeys[socket]);
                            socket.Send(encryptedResponse);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[GRESKA] Ne mogu poslati odgovor: {e.Message}");
                            zaUkloniti.Add(socket);
                            continue;
                        }

                        if (odgovor.ToLower() == "kraj")
                        {
                            Console.WriteLine($"[INFO] Klijent {socket.RemoteEndPoint} zatvoren komandom 'kraj' sa servera.");
                            zaUkloniti.Add(socket);
                        }
                    }
                }

                foreach (var s in zaUkloniti)
                {
                    try { s.Shutdown(SocketShutdown.Both); } catch { }
                    s.Close();
                    clients.Remove(s);
                    clientKeys.Remove(s);
                    clientInfo.Remove(s);
                }

                // ✅ Ako nema više nijednog klijenta — zatvori server i izađi
                if (clients.Count == 0)
                {
                    Console.WriteLine("[INFO] Nema više aktivnih klijenata. Zatvaram TCP AES server.");
                    try { listener.Close(); } catch { }
                    return;
                }
            }
        }
    }
}
