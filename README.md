# PQC-Alg-Compare

Dieses GitHub-Repository beinhaltet alle benötigten Libs, Codes und Daten, um den Compare auf Raspi's auszuführen.

Implementiert sind die einzelnen Algorithmen jeweils mit einer Client/Server-Architektur.
Als Grundlage dazu diente die Masterthesis "Evaluation of Post Quantum
Cryptography on IOT Hardware" von Niyati Tumkur Venugopal aus September 2024.

Verbessert wurde die Kommunikation - nicht mehr File-Based oder Socket-Based - durch eine REST-API.

Im Branch "IT-Projekt" werden die Daten aus einer in der Masterthesis verwendeten URL mit der aus der Masterthesis genutzten Methode gefetched.
Die prinzipiellen Workflows wurden beibehalten.
Zusätzlich werden nun mehr Daten erhoben. Einzusehen sind diese in der Vergleichsoberfläche.
Was bei den jeweiligen Algorithmen-Varianten zu beachten ist, um sie zu starten, ist in den jeweiligen README's dokumentiert.

Kyber:                  cw
Sphincs:                cw
Diffie-Hellmann:        cw
Vergleichsoberfläche:   cw
