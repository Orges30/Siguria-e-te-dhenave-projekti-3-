# Siguria-e-te-dhenave-projekti-i-3-
# Implementimi i një Handshake të Thjeshtuar SSH në Arkitekturë Client-Server

## Projekti i lëndës: Siguri e të Dhënave

---

# Përshkrimi i Projektit

Ky projekt paraqet implementimin e një versioni të thjeshtuar të protokollit SSH (Secure Shell) duke përdorur arkitekturën Client-Server në gjuhën programuese Python. Qëllimi kryesor i projektit është simulimi i fazave fillestare të një komunikimi të sigurt SSH ndërmjet një klienti dhe një serveri, duke demonstruar procesin e vendosjes së një kanali të sigurt komunikimi përmes përdorimit të teknikave moderne të kriptografisë.

Në implementimin e këtij projekti janë përdorur konceptet themelore të sigurisë së komunikimit në rrjet, si negocimi i algoritmeve, shkëmbimi i çelësave përmes Diffie-Hellman, autentifikimi i serverit përmes nënshkrimeve digjitale RSA, gjenerimi i session key dhe krijimi i një komunikimi të sigurt ndërmjet palëve.

Ky projekt synon të demonstrojë në mënyrë praktike mënyrën se si funksionon handshake-i i SSH-së dhe si përdoren mekanizmat kriptografikë për të parandaluar sulme të ndryshme si Man-in-the-Middle (MITM), falsifikimi i identitetit të serverit dhe ndërhyrjet gjatë komunikimit.

---

# Qëllimi i Projektit

Qëllimi i këtij projekti është të demonstrojë praktikisht funksionimin e protokollit SSH gjatë fazës së handshake-it dhe krijimit të një komunikimi të sigurt ndërmjet klientit dhe serverit. Përmes këtij implementimi synohet të kuptohet mënyra se si realizohet autentifikimi i serverit, si bëhet shkëmbimi i çelësave pa i transmetuar ata drejtpërdrejt në rrjet dhe si krijohet një session key i përbashkët për komunikim të sigurt.

Gjithashtu, projekti ndihmon në kuptimin e përdorimit të teknikave të kriptografisë moderne në aplikacione reale të sigurisë së rrjeteve dhe demonstron mënyrën se si ndërtohet një protokoll i sigurt komunikimi në praktikë.

---

# Teknologjitë e Përdorura

Në këtë projekt janë përdorur teknologjitë dhe bibliotekat në vijim:

- Python 3
- Socket Programming
- Biblioteka cryptography
- RSA Digital Signatures
- Diffie-Hellman Key Exchange
- SHA256 Hashing
- HKDF për derivimin e çelësave

Python është përdorur si gjuhë programuese kryesore për shkak të thjeshtësisë dhe mbështetjes së mirë për programim të rrjeteve dhe operacione kriptografike. Biblioteka cryptography është përdorur për implementimin e funksioneve të sigurisë si gjenerimi i çelësave, nënshkrimet digjitale dhe derivimi i session key.

---

# Struktura e Projektit

```text
ssh-project/
│
├── server.py
├── client.py
├── crypto_utils.py
├── requirements.txt
├── README.md
├── known_hosts.json
├── .gitignore
```
# Përshkrimi i Detajuar i File-ve

## server.py

File-i `server.py` përfaqëson anën e serverit në arkitekturën client-server dhe është komponenti kryesor përgjegjës për menaxhimin e handshake-it SSH nga ana e serverit. Ky file fillimisht krijon një TCP socket dhe fillon të dëgjojë për lidhje hyrëse nga klientët në një port të caktuar. Pasi klienti lidhet me sukses, serveri fillon procesin e handshake-it duke pranuar algoritmet e propozuara nga klienti dhe duke zgjedhur algoritmet që do të përdoren gjatë komunikimit.

Më pas serveri gjeneron çelësat RSA të cilët përdoren për autentifikimin e identitetit të serverit. Pas kësaj gjenerohen parametrat dhe çelësat Diffie-Hellman për realizimin e key exchange. Serveri nënshkruan çelësin publik Diffie-Hellman me çelësin privat RSA për të dëshmuar identitetin e tij dhe për të parandaluar sulmet Man-in-the-Middle (MITM).

Në fund serveri pranon çelësin publik Diffie-Hellman nga klienti, krijon shared secret dhe derivon session key përmes HKDF dhe SHA256. Pas përfundimit me sukses të të gjitha hapave të handshake-it, serveri konfirmon krijimin e kanalit të sigurt të komunikimit.

Ky file përmban gjithashtu:
- logging të detajuar për secilin hap të handshake-it
- menaxhim të gabimeve për raste të ndryshme
- konfigurimin e algoritmeve të mbështetura
- komunikimin përmes socket programming

---

## client.py

File-i `client.py` përfaqëson anën e klientit në komunikimin SSH dhe ka përgjegjësi të iniciojë lidhjen me serverin dhe të realizojë të gjitha fazat e handshake-it nga perspektiva e klientit.

Klienti fillimisht lexon databazën `known_hosts.json` për të kontrolluar nëse serveri është i njohur dhe i besueshëm. Kjo simulon mekanizmin real të SSH-së për verifikimin e hosteve dhe ndihmon në mbrojtjen kundër serverëve të rremë ose sulmeve MITM.

Pas krijimit të lidhjes TCP me serverin, klienti dërgon listën e algoritmeve që mbështet për key exchange, encryption dhe hashing. Klienti më pas pranon algoritmet e zgjedhura nga serveri dhe të dhënat e autentifikimit të serverit.

Një pjesë shumë e rëndësishme e këtij file-i është verifikimi i identitetit të serverit. Klienti përdor çelësin publik RSA të serverit për të verifikuar nënshkrimin digjital të çelësit publik Diffie-Hellman të serverit. Nëse verifikimi dështon, komunikimi ndërpritet menjëherë për arsye sigurie.

Pas verifikimit të suksesshëm, klienti gjeneron çelësat e tij Diffie-Hellman, shkëmben çelësin publik me serverin dhe krijon session key përmes shared secret të gjeneruar.

Ky file përfshin:
- inicializimin e lidhjes me serverin
- host verification
- algorithm negotiation
- digital signature verification
- session key generation
- logging dhe error handling

---

## crypto_utils.py

File-i `crypto_utils.py` përmban të gjitha funksionet ndihmëse të kriptografisë të përdorura nga klienti dhe serveri. Qëllimi i këtij file-i është modularizimi i logjikës së sigurisë dhe ndarja e operacioneve kriptografike nga logjika kryesore e komunikimit.

Në këtë file implementohen funksione për:
- gjenerimin e çelësave RSA
- krijimin e nënshkrimeve digjitale
- verifikimin e signature
- gjenerimin e parametrave Diffie-Hellman
- krijimin e shared secret
- derivimin e session key
- serializimin dhe deserializimin e çelësave

RSA përdoret për autentifikimin e serverit përmes digital signatures, ndërsa Diffie-Hellman përdoret për key exchange dhe krijimin e shared secret pa e transmetuar atë në rrjet.

HKDF dhe SHA256 përdoren për derivimin e session key nga shared secret në mënyrë të sigurt dhe të standardizuar.

Ky file është shumë i rëndësishëm sepse centralizon të gjitha operacionet e sigurisë dhe e bën kodin:
- më të organizuar
- më të lexueshëm
- më të mirëmbajtshëm
- më profesional

---

## known_hosts.json

File-i `known_hosts.json` simulon databazën e hosteve të njohur të SSH-së, ngjashëm me file-in `known_hosts` në sistemet reale Linux dhe Unix. Ky file përdoret nga klienti për të kontrolluar nëse serveri me të cilin po lidhet konsiderohet i besueshëm.

Brenda këtij file-i ruhen informata si:
- IP adresa e serverit
- emri i serverit
- statusi trusted
- algoritmet e mbështetura

Para fillimit të handshake-it, klienti lexon këtë file dhe kontrollon nëse serveri ekziston në databazë dhe nëse është i autorizuar për komunikim. Nëse serveri nuk gjendet ose nuk konsiderohet trusted, lidhja ndërpritet.

Ky mekanizëm ndihmon në:
- host verification
- parandalimin e lidhjeve me serverë të rremë
- simulimin realist të SSH-së

---

## requirements.txt

File-i `requirements.txt` përmban listën e bibliotekave të nevojshme për ekzekutimin e projektit. Në këtë projekt përdoret biblioteka `cryptography`, e cila ofron implementimin e algoritmeve moderne të kriptografisë si RSA, Diffie-Hellman, hashing dhe HKDF.

Ky file lehtëson instalimin e dependencies dhe siguron që projekti të mund të ekzekutohet lehtësisht në çdo kompjuter duke përdorur komandën:
---