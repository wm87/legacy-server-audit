![Ansible](https://img.shields.io/badge/Ansible-2.9+-red.svg?logo=ansible\&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.0+-blue.svg?logo=gnu-bash\&logoColor=white)
![Lizenz](https://img.shields.io/badge/Lizenz-MIT-green.svg)
![Plattform](https://img.shields.io/badge/Plattform-Linux-lightgrey.svg?logo=linux\&logoColor=white)
[![Sicherheits-Audit](https://img.shields.io/badge/Security-Audit-blue)](https://github.com/yourusername/legacy-server-audit)
![Security](https://img.shields.io/badge/Sicherheit-CIS%20Compliant-orange.svg)

# Legacy Server Security Audit Framework

Das **Legacy Server Audit Project Generator** ist ein leistungsstarkes Bash-Skript, das mit nur einem Befehl ein vollständiges, produktionsreifes Ansible-Audit-Projekt erstellt. Viele Unternehmen stehen vor der Herausforderung, ältere Server zu übernehmen, ohne genau zu wissen, welche Software oder Konfigurationen darauf laufen – das kann schnell komplex und unübersichtlich werden.

Dieses Projekt automatisiert den gesamten Sicherheits-Audit-Prozess für Legacy-Server: von der Einhaltung von CIS Benchmarks über die Schwachstellenerkennung bis hin zur automatischen Berichterstellung. So können Teams sofort fundierte Entscheidungen treffen, Sicherheitsrisiken priorisieren und den Überblick über selbst komplexe Alt-Systeme behalten – alles ohne mühsame manuelle Analyse.

# 🔧 Technische Features

## ✅ Vollständige Automation

* Ein-Klick-Generierung: Komplettes Projekt mit einem Befehl
* Farbcodierte Ausgabe: Übersichtliche Statusmeldungen
* Idempotent: Sichert existierende Daten
* Interaktiv: Bestätigung bei Überschreibung

## ✅ Umfassende Audit-Coverage

* CIS Benchmarks: 100+ spezifische Checks
* Netzwerk-Sicherheit: Ports, Firewalls, SSH
* System-Härtung: Kernel, Services, Benutzer
* Compliance: PCI-DSS, HIPAA Erkennung
* Secrets-Management: Hardcodierte Credentials

## ✅ Intelligente Berichterstellung

* Mehrere Formate: JSON, Markdown, HTML (via Pandoc)
* Risiko-Scoring: Gewichtete Bewertung (0-100)
* Redflags-Aggregation: Automatische Risikoidentifikation
* Executive Summaries: Management-freundliche Berichte

## ✅ Produktionsfeatures

* Check Mode: Safe Prüfung ohne Änderungen
* Remediation Playbooks: Auto-generierte Fixes
* SOPS Integration: Secrets-Migrationsvorschläge
* Backup-System: Automatische Sicherungen

# 🏗️ Projektstruktur

```text
PROJEKTNAME/
├── ansible.cfg
├── audit.yml
├── setup.sh
├── run-audit.sh
├── Makefile
├── requirements.yml
├── .gitignore
│
├── inventory/
│   └── hosts.ini
│
├── vars/
│   └── audit_vars.yml
│
├── roles/audit/
│   ├── defaults/main.yml
│   ├── meta/main.yml
│   ├── handlers/main.yml
│   └── tasks/
│       ├── main.yml
│       ├── cis/level1/main.yml
│       ├── cis/level2/main.yml
│       ├── ports.yml
│       ├── services.yml
│       ├── users.yml
│       ├── cron.yml
│       ├── packages.yml
│       ├── security.yml
│       ├── secrets.yml
│       ├── containers.yml
│       ├── world_writable.yml
│       ├── ssh_keys.yml
│       ├── inactive_users.yml
│       ├── env_secrets.yml
│       ├── logrotate.yml
│       ├── suid_sgid.yml
│       ├── ipv6_ports.yml
│       ├── failed_logins.yml
│       ├── crypto.yml
│       ├── permissions.yml
│       ├── sysctl.yml
│       ├── updates.yml
│       ├── password_age.yml
│       ├── auditd.yml
│       ├── network.yml
│       ├── logging.yml
│       ├── compliance.yml
│       ├── risk_expiry.yml
│       ├── redflags.yml
│       ├── fixes.yml
│       ├── severity.yml
│       ├── json.yml
│       ├── sops_proposals.yml
│       ├── remediation.yml
│       ├── reporting.yml
│       ├── sudoers.yml
│       ├── kernel.yml
│       ├── boot.yml
│       ├── filesystem.yml
│       ├── firewall.yml
│       └── disk.yml
│
├── reports/
├── policies/
├── proposals/
├── certificates/
└── backups/
```

# 📊 Audit-Module im Detail

## 1. CIS Compliance (Level 1 & 2)

```text
├── cis/level1/main.yml
└── cis/level2/main.yml
```

## 2. Netzwerk-Sicherheit

* Port-Scanning (TCP/UDP, IPv4/IPv6)
* Firewall-Regelanalyse (iptables/ufw/firewalld)
* SSH-Härtungskonfiguration
* Netzwerkschnittstellen-Sicherheit

## 3. System-Sicherheit

* Kernel-Parameter (sysctl) Prüfung
* Dienst-Minimierung und Deaktivierung
* Benutzer- und Gruppenmanagement
* Dateiberechtigungen und SUID/SGID

## 4. Schwachstellen-Erkennung

* Bekannte CVE in Paketen
* Unsichere Konfigurationen
* Privilege-Escalation Vektoren
* Hardcodierte Secrets und Credentials

## 5. Compliance & Reporting

* Automatische Framework-Erkennung
* Risiko-Score Berechnung (0-100)
* Executive Summary Generierung
* Maßnahmenpriorisierung

# ⚙️ Konfiguration

## Inventory (`inventory/hosts.ini`)

```ini
[legacy_servers]
server1 ansible_host=192.168.1.100 ansible_user=audit_user
server2 ansible_host=192.168.1.101 ansible_user=audit_user

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=true
ansible_become_method=sudo
```

## Audit Variablen (`vars/audit_vars.yml`)

```yaml
audit_cis_level: 2
audit_max_severity: 10

# Thresholds
disk_threshold: 85
password_max_age: 90
inactive_user_days: 90

# Security Policies
allowed_ssh_ciphers: "chacha20-poly1305@openssh.com"
exclude_paths: ["/proc", "/sys", "/dev"]
```

# 🎮 Verwendung

## Entwicklungsumgebung einrichten

```bash
git clone https://github.com/wm87/legacy-server-audit.git
cd legacy-server-audit

bash setup.sh

# weiteren Anweisungen der Konsole folgen
# bzw. audit starten mit
make audit
```

## Makefile Targets

```bash
make audit
make report
make clean
make backup
make validate
make setup
```

## Erweiterte Optionen

```bash
ansible-playbook audit.yml --tags "cis,firewall"
ansible-playbook audit.yml --limit "server1,server2"
ansible-playbook audit.yml -vvv
ansible-playbook audit.yml -f 20
```

## Generierte Berichte

```text
reports/
├── audit-server1-1705327200.json
├── audit-server1-1705327200.md
├── executive-summary-2026-01-29.md
└── executive-summary-2026-01-29.html
```

# 🛡️ Sicherheitsmerkmale

## Safe Execution

* Check Mode Standard: Keine Systemänderungen
* Idempotente Tasks
* Backup-System
* Permission Checks

## Datenschutz

* Lokale Verarbeitung
* Keine externen Calls

# 📊 Risikobewertungssystem

| Risikokategorie | Gewichtung | Beispiele                           |
| --------------- | ---------- | ----------------------------------- |
| Kritisch        | 6 Punkte   | Plaintext Secrets, Kritische CVEs   |
| Hoch            | 5 Punkte   | SSH Misconfig, Passwordless Sudo    |
| Mittel          | 4 Punkte   | Unsichere Dienste, Weak Permissions |
| Niedrig         | 2-3 Punkte | Best Practice Verletzungen          |

**Risikolevel basierend auf Gesamt-Score:**

* 0-14: Niedrig (✅)
* 15-29: Mittel (⚠️)
* 30-49: Hoch (🔴)
* 50+: Kritisch (🚨)

# 🔧 Anpassung und Erweiterung

## Eigene Checks hinzufügen

```yaml
- name: Benutzerdefinierter Sicherheitscheck
  block:
    - name: Spezifische Konfiguration prüfen
      command: check_meine_config
      register: ergebnis
    - name: Risiko bewerten
      set_fact:
        audit_custom_issue: "{{ ergebnis.rc != 0 }}"
```

## Variablen anpassen

```yaml
audit_cis_level: 1
custom_thresholds:
  max_open_ports: 50
  min_password_length: 12
```

## Reporting erweitern

```yaml
## Benutzerdefinierter Bericht
Server: {{ ansible_hostname }}
Custom Check: {{ audit_custom_result }}
```

# 🧪 Testing & Validation

## Prüfungen vor der Ausführung

```bash
ansible-playbook --syntax-check audit.yml
ansible-lint audit.yml
ansible-playbook audit.yml --check
ansible-playbook audit.yml --tags "ssh,firewall" --check
```

# 📚 Best Practices

## Für Audit-Execution

* Immer --check zuerst
* Backups erstellen
* Staging nutzen
* Dokumentieren

## Für Projekt-Management

* Versionierung
* Templates pflegen
* Regelmäßige Updates
* Review-Prozess

# 🔍 Fehlerbehebung

| Problem                     | Lösung                                                |
| --------------------------- | ----------------------------------------------------- |
| "Permission denied" bei SSH | ansible_ssh_private_key_file in Inventory setzen      |
| Python nicht gefunden       | ansible_python_interpreter in Inventory setzen        |
| Sudo-Passwort erforderlich  | ansible_become_password setzen oder SSH-Key verwenden |
| Host nicht erreichbar       | Firewall, Netzwerk, SSH-Daemon prüfen                 |
| "Module not found"          | ./setup.sh ausführen für Dependencies                 |

## Debug-Modus

```bash
ansible-playbook audit.yml -vvv
ANSIBLE_DEBUG=1 ansible-playbook audit.yml --tags "ports"
time ansible-playbook audit.yml
```

# Pull Request Prozess

* Fork das Repository
* Feature-Branch erstellen
* Änderungen committen
* Push zum Branch
* Pull Request erstellen

# 🎉 Nächste Schritte

* Anpassen: Inventory und Variablen konfigurieren
* Testen: --check Modus
* Produktiv: Auf echten Servern ausführen
* Automatisieren: In CI/CD Pipeline integrieren
* Verschlüsselte Berichte

# 📄 Lizenz

**MIT License** - siehe LICENSE Datei

* Kommerzielle Nutzung erlaubt
* Modifikation erlaubt
* Private Nutzung erlaubt
* Haftungsausschluss: Tool garantiert keine vollständige Sicherheit
