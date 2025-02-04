TODO's, um die Sphincs-Implementierung auf zwei Raspi's zu nutzen:<br>

Begriffe:<br>
Server-Raspi: Der Raspi, auf dem der Server-Code gehostet werden soll<br>
Client-Raspi: Der Rapso, auf dem der Client-Code gehostet werden soll

1. Folgende Befehle auf dem Server-Raspi ausführen:<br>

sudo apt install libssl-dev<br>
sudo apt install libcurl4-openssl-dev<br>
sudo apt install libmicrohttpd-dev<br>
sudo apt install ufw<br>
sudo ufw allow 8080<br>
git clone https://github.com/floswrld/PQC-Alg-Compare.git<br>
cd PQC-Alg-Compare/Sphincs<br>
make<br>
./ServerSphincs<br>

2. Folgende Befehle auf dem Client-Raspi ausführen:<br>

sudo apt install libssl-dev<br>
sudo apt install libcurl4-openssl-dev<br>
sudo apt install libmicrohttpd-dev<br>
git clone https://github.com/floswrld/PQC-Alg-Compare.git<br>
cd PQC-Alg-Compare/Sphincs<br>
make<br>
./ClientSphincs<br>

Der Client fragt nun nach dem Server, mit dem er sich verbinden möchte. Dazu die vom Server angezeigte ip-address:host kopieren, einfügen und entern.

Nun läuft der Algorithmus.
Die Messdaten werden in der File "sphincs.csv" auf dem Client-Raspi gesichert
