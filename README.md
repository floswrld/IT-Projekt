# PQC-Alg-Compare

Dieses GitHub-Repository beinhaltet alle benötigten Libs, Codes und Daten, um den Compare auf Raspi's auszuführen.

Implementiert sind die einzelnen Algorithmen jeweils mit einer Client/Server-Architektur.
Als Grundlage dazu diente die Masterthesis "Evaluation of Post Quantum
Cryptography on IOT Hardware" von Niyati Tumkur Venugopal aus September 2024.

Verbessert wurde die Kommunikation - nicht mehr File-Based oder Socket-Based - durch eine REST-API.

Im Branch [IT-Projekt](https://github.com/floswrld/PQC-Alg-Compare/blob/IT-Projekt/)
 werden die Daten aus einer in der Masterthesis verwendeten URL mit der aus der Masterthesis genutzten Methode gefetched.<br>
Im Branch [IT-Sicherheit](https://github.com/floswrld/PQC-Alg-Compare/blob/IT-Sicherheit/) werden die Daten aus einer JSON geladen. Diese liegt in [Data-Preprocesing](https://github.com/floswrld/PQC-Alg-Compare/blob/IT-Sicherheit/Data-Preprocessing/), in der auch ein [Python-Skript](https://github.com/floswrld/PQC-Alg-Compare/blob/IT-Sicherheit/Data-Preprocessing/dataPreProcessing.py) verfügbar ist, das eine zugrundeliegende Excel mit bestimmten Format in eine JSON-File umwandelt.<br>

Die prinzipiellen Workflows wurden beibehalten.
Zusätzlich werden nun mehr Daten erhoben. Einzusehen sind diese in der Vergleichsoberfläche.
Was bei den jeweiligen Algorithmen-Varianten zu beachten ist, um sie zu starten, ist in den jeweiligen README's dokumentiert.

Kyber:                  [README-Kyber](/Kyber/README-Kyber.md)<br>
Sphincs:                [README-Sphincs](/Sphincs/README-Sphincs.md)<br>
Diffie-Hellman:         [README-DH](/Diffie-Hellman/README-DH.md)<br>
Visualisierung:         [Visualisierung](/Visualisierung/)
