# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Prérequis

- Python 3.11 ou plus
- Poetry
- Windows : [Npcap](https://npcap.com/) (installé avec Wireshark)
- Droits administrateur (root sous Linux) pour la capture réseau

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## TP1 - IDS/IPS maison

### Lancement

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

Écrit `report.json` et `report.pdf` (à côté du JSON, ou chemin donné par `--pdf`).

Pour le développement, capture live (droits administrateur) :

```bash
poetry run tp1 --iface eth0 --count 200 --timeout 30
```

Sans `--pcap` ni `--iface`, le programme propose la liste des interfaces.

### Fonctionnement

| Étape | Fichier | Rôle |
|---|---|---|
| Arguments | `main.py` | `--pcap`, `--iface`, `--out`, `--pdf` |
| Capture | `utils/capture.py` | lecture du PCAP (`rdpcap`) ou `sniff` live |
| Statistiques | `utils/capture.py` | paquets par protocole : Ethernet, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, HTTP |
| Détection | `utils/analysis.py` | attaques, flag, règles de blocage |
| Rapports | `utils/report.py` | `report.json` et PDF (tableau, graphique, attaques) |

Un paquet est compté dans chacune de ses couches : une requête HTTP compte pour Ethernet, IP, TCP et HTTP.
HTTP est reconnu par son contenu (méthode ou `HTTP/`), quel que soit le port.

### Attaques détectées

- **ARP spoofing** (`arp_spoofing`, attaquant = MAC) : une IP annoncée par plusieurs MAC (la première vue est
  considérée comme légitime), ou réponses ARP non sollicitées pour plusieurs IP depuis une même MAC.
- **Scan de ports** (`port_scan`, attaquant = IP) : au moins 10 ports différents sondés depuis une même source
  (SYN sans ACK, ainsi que FIN/NULL/XMAS).
- **Injection SQL** (`sql_injection`, attaquant = IP) : motifs SQL (`' OR 1=1`, `UNION SELECT`, `; DROP`,
  `SLEEP(`...) dans les requêtes HTTP, après décodage URL.

### Flag

Le flag `ESGI{...}` est cherché en clair, encodé URL ou en base64. Si plusieurs sont présents, celui envoyé par
un attaquant dans une requête malveillante est retenu ; les leurres sont écartés.

### Blocage (facultatif)

Une règle `iptables` est proposée pour chaque attaquant dans le PDF et dans les logs :
`-s <ip>` pour une IP, `-m mac --mac-source <mac>` pour une MAC.

### Sorties

```json
{
  "protocols": {"Ethernet": 143, "IP": 123, "TCP": 95, "ARP": 20},
  "attacks": [{"type": "port_scan", "attacker": "192.168.193.66"}],
  "flag": "ESGI{...}"
}
```

Les logs sont écrits sur la sortie d'erreur.

## Tests

```bash
poetry run pytest tests/tp1
```

## TP3 - Breach the target

Exploit automatisé en deux phases : web (fuzzing + CAPTCHA) puis réseau
(décodage chronométré). Affiche les deux drapeaux.

### Lancement

```bash
poetry run tp3 --target http://localhost:8080
```

Sortie attendue :

```
[+] FLAG1: ESGI{web_...}
[+] FLAG_FINAL: ESGI{chain_...}
```

### Fonctionnement

| Étape | Fichier | Rôle |
|---|---|---|
| Fuzzing | `utils/session.py` | `find_hidden_endpoint` teste la wordlist embarquée (`utils/wordlist.txt`) et retient la page interne (200 + formulaire CAPTCHA) |
| CAPTCHA | `utils/captcha.py` | télécharge `/captcha.png` (cookie de session partagé), prétraite (PIL : gris, agrandissement, seuillage, débruitage) et lit le code (pytesseract, vote multi-seuils, ~95 % au 1er essai) |
| Soumission | `utils/session.py` | `Session` poste le code, parse `{flag1, host, port, key}`, réessaie l'OCR jusqu'à 12 fois |
| Réseau | `utils/netcode.py` | connexion TCP, boucle base64→XOR(clé) sous 5 s/round, renvoie le flag final |

La wordlist est embarquée et ouverte par un chemin **relatif au code**
(`Path(__file__).parent / "wordlist.txt"`), l'exploit fonctionne donc depuis
un répertoire de travail vide et sans accès Internet (contraintes de
l'instance hébergée). Si l'hôte TCP annoncé est une boucle locale, l'exploit
bascule sur l'hôte du `--target`.

### Cible de développement (local)

```bash
docker load -i tp3-target.tar.gz
docker compose up      # Web :8080, TCP :9090, drapeaux factices
```

### Tests

```bash
poetry run pytest tests/tp3
```
