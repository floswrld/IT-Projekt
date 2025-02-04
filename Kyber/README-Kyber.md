TODO's, um die Kyber-Implementierung auf zwei Raspi's zu nutzen:

Begriffe:
Server-Raspi: Der Raspi, auf dem der Server-Code gehostet werden soll
Client-Raspi: Der Rapso, auf dem der Client-Code gehostet werden soll

1. Folgende Befehle auf dem Server-Raspi ausführen:

sudo apt install libssl-dev
sudo apt install libcurl4-openssl-dev
sudo apt install libmicrohttpd-dev
sudo apt install ufw
sudo ufw allow 8080
git clone https://github.com/floswrld/PQC-Alg-Compare.git
cd PQC-Alg-Compare/Kyber
make
./ServerKyber

2. Folgende Befehle auf dem Client-Raspi ausführen:

sudo apt install libssl-dev
sudo apt install libcurl4-openssl-dev
sudo apt install libmicrohttpd-dev
git clone https://github.com/floswrld/PQC-Alg-Compare.git
cd PQC-Alg-Compare/Kyber
make
./ClientKyber

Der Client fragt nun nach dem Server, mit dem er sich verbinden möchte. Dazu die vom Server angezeigte <ip-address>:<host> kopieren, einfügen und entern.

Nun läuft der Algorithmus.
Die Messdaten werden in der File "kyber.csv" auf dem Client-Rapsi gesichert
