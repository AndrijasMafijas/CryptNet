# 🔐 CryptNet (RSA + AES / 3DES)

Ovaj projekat predstavlja implementaciju sigurnog sistema za razmenu poruka između klijenta i servera koristeći:

- **UDP i TCP** protokole
- **RSA** za asimetričnu razmenu ključeva
- **3DES** i **AES** za simetričnu enkripciju komunikacije

## 🚀 Funkcionalnosti

✅ Dinamičko biranje protokola i algoritma (TCP/UDP, 3DES/AES)  
✅ Razmena RSA ključeva između klijenta i servera  
✅ Sigurno slanje simetričkog ključa (kriptovan RSA-om)  
✅ Enkriptovana komunikacija poruka između klijenta i servera  
✅ Mogućnost više istovremenih TCP klijenata  
✅ Automatsko gašenje servera kada svi klijenti završe komunikaciju (`kraj` komanda)  
✅ Statistika količine enkriptovanih i dekriptovanih bajtova

## 🧪 Kako pokrenuti

1. Pokreni prmuis->server->server.sln (Visual Studio)
2. Server čeka inicijalnu UDP poruku klijenta sa:
3. - `Protokol`: `1` za TCP, `2` za UDP
- `Algoritam`: `1` za 3DES, `2` za AES
- `Port`: port na kojem klijent želi da komunicira
3. Server odgovara javnim RSA ključem
4. Klijent šalje simetrični ključ kriptovan RSA-om
5. Komunikacija može da počne

## 📌 Komande

- `kraj` – koristi se sa strane klijenta ili servera za prekid konekcije
- Kada svi aktivni klijenti pošalju `kraj` ili im server pošalje `kraj` → server se automatski gasi

## 📊 Statistika

Na kraju izvršavanja prikazuje se statistika:

===== Statistika enkripcije i dekripcije =====
AES - Enkriptovano ukupno: XXX bajtova
AES - Dekriptovano ukupno: XXX bajtova
3DES - Enkriptovano ukupno: XXX bajtova
3DES - Dekriptovano ukupno: XXX bajtova

## 🔧 Tehnologije

- C# (.NET)
- Sockets (TCP/UDP)
- RSA, AES, TripleDES
- Base64, SHA-256 hashiranje

## 🧠 Autor

- 👤 Andrija Stanišić
- 👤 Stefan Cimbaljević

## 📝 Napomena

Ovaj projekat je edukativnog karaktera i demonstrira osnovne koncepte sigurne komunikacije. Nije namenjen za produkcionu upotrebu bez dodatne validacije i zaštite.
