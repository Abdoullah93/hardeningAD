# 🛡️ Travaux Pratiques — Hardening Active Directory
### Windows Server 2022 · Purple Knight · HardenAD
**Durée : 7 heures | Niveau : Ingénieur | Version : 1.0**

---

> **⚠️ Règle d'or — À lire avant toute action**
> Toute modification de l'Active Directory doit être précédée d'un **snapshot de la VM**. Sans snapshot, pas d'action. Cette règle est non-négociable et fait partie de l'évaluation.

---

## Sommaire

| # | Module | Durée |
|---|--------|-------|
| 0 | Environnement & Règles de sécurité | 15 min |
| **MATIN** | | |
| 1 | État des lieux — Audit initial | 45 min |
| 2 | Création de vulnérabilités contrôlées | 45 min |
| 3 | Audit après vulnérabilisation | 30 min |
| 4 | Remédiation manuelle (PowerShell) | 45 min |
| 5 | Audit de validation | 30 min |
| **APRÈS-MIDI** | | |
| 6 | Introduction à HardenAD | 30 min |
| 7 | Exploration du dépôt HardenAD | 30 min |
| 8 | Hardening par paliers avec HardenAD | 90 min |
| 9 | Audit final et comparaison | 30 min |
| 10 | Rapport & Grille d'évaluation | — |

---

## Module 0 — Environnement & Règles de sécurité

### Prérequis techniques

| Composant | Valeur attendue |
|-----------|----------------|
| OS | Windows Server 2022 |
| Rôle | Contrôleur de domaine (PDC) |
| Domaine exemple | `lab.local` |
| Compte de travail | Administrateur du domaine |
| Outils à installer | Purple Knight, HardenAD |
| Répertoire de travail | `C:\HAD\` |
| Répertoire des rapports | `C:\HAD\Reports\` |

### Installation de l'environnement

```powershell
# 1. Cloner HardenAD
git clone https://github.com/LoicVeirman/HardenAD C:\HAD

# 2. Autoriser l'exécution des scripts
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Débloquer les fichiers téléchargés
Get-ChildItem C:\HAD -Recurse | Unblock-File

# 4. Créer le répertoire des rapports
New-Item -ItemType Directory -Path C:\HAD\Reports -Force

# 5. Activer le module ActiveDirectory si besoin
Add-WindowsFeature RSAT-AD-PowerShell
```

### Règles de sécurité (obligatoires)

```
┌─────────────────────────────────────────────────────────────────────┐
│  AVANT toute remédiation  →  Snapshot VM                           │
│  APRÈS toute remédiation  →  Audit + Snapshot VM                   │
│  En cas d'anomalie        →  Rollback snapshot + documenter        │
│  Jamais sur un DC de production                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Nommage des snapshots

Adoptez systématiquement la convention suivante :

```
snapshot_initial_YYYY-MM-DD
snapshot_pre_<action>_YYYY-MM-DD
snapshot_post_<action>_YYYY-MM-DD
```

---

---

# 🌅 MATIN — Méthode Manuelle & Audit

---

## Module 1 — État des lieux : Audit initial

> **Objectif :** Comprendre l'état de santé de l'AD *avant* toute modification. Ce « baseline » servira de référence pour mesurer l'impact de vos actions.

### 📸 Action obligatoire — Snapshot initial

Avant de commencer, prenez un snapshot de la VM :

```
Hyper-V Manager → Clic droit sur la VM → Checkpoint
Nom : snapshot_initial_YYYY-MM-DD
```

---

### 1.1 — Inventaire des comptes Active Directory

#### Concept : Pourquoi inventorier ?

Un AD mal géré accumule des comptes obsolètes, des comptes de service exposés, et des membres fantômes dans les groupes privilégiés. L'inventaire est la première étape de tout audit.

#### Lister tous les utilisateurs

```powershell
# Tous les utilisateurs du domaine
Get-ADUser -Filter * -Properties * |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet,
                  PasswordNeverExpires, ServicePrincipalNames |
    Sort-Object Name |
    Format-Table -AutoSize
```

#### Lister les groupes privilégiés

```powershell
# Membres du groupe Domain Admins
Get-ADGroupMember -Identity "Admins du domaine" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass

# Membres du groupe Enterprise Admins
Get-ADGroupMember -Identity "Administrateurs de l'entreprise" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass

# Membres du groupe Schema Admins
Get-ADGroupMember -Identity "Administrateurs du schéma" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass
```

#### Lister les comptes de service (Kerberoastable)

```powershell
# Comptes avec un SPN défini = potentiellement Kerberoastables
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalNames |
    Select-Object Name, SamAccountName, ServicePrincipalNames
```

#### Rechercher des comptes à risque

```powershell
# Comptes avec mot de passe qui n'expire jamais
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires |
    Select-Object Name, SamAccountName

# Comptes désactivés encore présents dans des groupes privilégiés
Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf |
    Where-Object { $_.MemberOf -ne $null } |
    Select-Object Name, SamAccountName, MemberOf
```

#### Inventaire des Unités d'Organisation (OU)

```powershell
# Structure des OU du domaine
Get-ADOrganizationalUnit -Filter * |
    Select-Object Name, DistinguishedName |
    Sort-Object DistinguishedName
```

> 📝 **Note pédagogique :** Exportez ces résultats dans `C:\HAD\Reports\baseline_inventory.txt` pour comparaison ultérieure.

```powershell
# Exporter l'inventaire
Get-ADUser -Filter * -Properties * |
    Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires, ServicePrincipalNames |
    Export-Csv -Path "C:\HAD\Reports\baseline_inventory.csv" -NoTypeInformation -Encoding UTF8
```

---

### 1.2 — Audit initial avec Purple Knight

#### Concept : Qu'est-ce que Purple Knight ?

Purple Knight est un outil d'audit AD développé par Semperis. Il analyse l'Active Directory à la recherche de **mauvaises configurations**, d'**indicateurs de compromission (IoC)** et de **risques de sécurité** connus. Il génère un score de sécurité et des rapports HTML/JSON.

> Purple Knight analyse notamment : délégations Kerberos non contraintes, comptes Kerberoastables, comptes avec droits DCSync, GPO mal configurées, mots de passe réversibles, etc.

#### Lancement de Purple Knight

1. Ouvrir PowerShell en tant qu'Administrateur
2. Naviguer vers le répertoire Purple Knight
3. Exécuter l'outil et sauvegarder le rapport

```powershell
# Sauvegarder le rapport baseline
Copy-Item "<chemin_rapport_PurpleKnight>\*.html" "C:\HAD\Reports\baseline_PK.html"
Copy-Item "<chemin_rapport_PurpleKnight>\*.json" "C:\HAD\Reports\baseline_PK.json"
```

> 📝 **À noter dans votre rapport :**
> - Le score global (sur 100)
> - Les 5 findings de criticité la plus élevée
> - Le nombre total de findings par catégorie

---

---

## Module 2 — Création de vulnérabilités contrôlées

> **Objectif :** Simuler un AD mal configuré, tel qu'on en trouve en production. Ces vulnérabilités volontaires permettront de tester les outils d'audit et les procédures de remédiation.

### 📸 Action obligatoire — Snapshot pré-vulnérabilisation

```
Nom : snapshot_pre_vulns_YYYY-MM-DD
```

---

### 2.1 — Concept : Les vulnérabilités que vous allez créer

| Vulnérabilité | Risque | Technique d'attaque |
|---------------|--------|---------------------|
| Compte avec mot de passe faible | Élevé | Brute force, Password spray |
| Compte avec SPN | Élevé | Kerberoasting |
| Utilisateur standard dans Domain Admins | Critique | Élévation de privilèges |
| Mot de passe qui n'expire jamais | Moyen | Persistence |

---

### 2.2 — Atelier : Création des comptes vulnérables

#### Étape 1 — Créer des utilisateurs standards avec mots de passe faibles

```powershell
# Utilisateur 1 : Alice Martin — mot de passe faible mais conforme à la politique
New-ADUser `
    -Name "Alice Martin" `
    -SamAccountName "amartin" `
    -GivenName "Alice" `
    -Surname "Martin" `
    -UserPrincipalName "amartin@lab.local" `
    -AccountPassword (ConvertTo-SecureString "P@ssword1" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Compte de test - vulnérable"

# Utilisateur 2 : Bob Dupont — mot de passe basé sur clavier AZERTY courant
New-ADUser `
    -Name "Bob Dupont" `
    -SamAccountName "bdupont" `
    -GivenName "Bob" `
    -Surname "Dupont" `
    -UserPrincipalName "bdupont@lab.local" `
    -AccountPassword (ConvertTo-SecureString "Azerty123!" -AsPlainText -Force) `
    -Enabled $true `
    -Description "Compte de test - vulnérable"
```

> 💡 **Pourquoi ces mots de passe sont-ils dangereux ?**
> `P@ssword1` et `Azerty123!` respectent les règles de complexité Windows (majuscule, minuscule, chiffre, caractère spécial) mais figurent dans les **listes de dictionnaires** d'attaque. Un attaquant les testera en quelques secondes via une attaque par *password spray*.

---

#### Étape 2 — Créer un compte de service Kerberoastable

```powershell
# Compte de service avec SPN = cible idéale pour Kerberoasting
New-ADUser `
    -Name "svc-backup" `
    -SamAccountName "svc-backup" `
    -UserPrincipalName "svc-backup@lab.local" `
    -AccountPassword (ConvertTo-SecureString "Backup2024" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Compte de service backup - vulnérable Kerberoasting"

# Assigner un SPN au compte (le rend Kerberoastable)
Set-ADUser "svc-backup" `
    -ServicePrincipalNames @{Add="MSSQLSvc/srv-backup.lab.local:1433"}
```

> 💡 **Concept Kerberoasting :**
> Tout utilisateur authentifié du domaine peut demander un **ticket de service Kerberos (TGS)** pour n'importe quel SPN. Ce ticket est chiffré avec le hash du mot de passe du compte de service. Un attaquant peut extraire ce ticket et le casser *hors ligne*. Si le mot de passe est faible (`Backup2024`), il sera craqué en quelques minutes avec Hashcat ou John the Ripper.

---

#### Étape 3 — Mauvaise pratique : Élévation non autorisée dans Domain Admins

```powershell
# Ajout d'un utilisateur standard dans le groupe le plus privilégié du domaine
Add-ADGroupMember -Identity "Admins du domaine" -Members "bdupont"
```

> 💡 **Pourquoi c'est critique ?**
> Le groupe **Domain Admins** dispose de droits sur l'ensemble du domaine. Un compte ordinaire (`bdupont`) avec un mot de passe faible (`Azerty123!`) qui se retrouve dans ce groupe est une **porte d'entrée grand ouverte** pour un attaquant. En production, cette configuration est malheureusement très fréquente.

---

### 2.3 — Vérification des vulnérabilités créées

```powershell
# Vérifier la création des trois comptes
Get-ADUser -Filter {
    SamAccountName -eq 'amartin' -or
    SamAccountName -eq 'bdupont' -or
    SamAccountName -eq 'svc-backup'
} -Properties PasswordNeverExpires, ServicePrincipalNames |
    Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires, ServicePrincipalNames

# Vérifier spécifiquement le SPN du compte de service
Get-ADUser -Identity "svc-backup" -Properties ServicePrincipalNames |
    Select-Object Name, ServicePrincipalNames

# Vérifier que bdupont est bien dans Domain Admins
Get-ADGroupMember -Identity "Admins du domaine" |
    Select-Object Name, SamAccountName
```

> ✅ **Résultat attendu :** Les trois comptes sont créés, `svc-backup` a un SPN `MSSQLSvc/srv-backup.lab.local:1433`, et `bdupont` apparaît dans les membres de *Admins du domaine*.

---

---

## Module 3 — Deuxième audit : mesurer la dégradation

> **Objectif :** Relancer Purple Knight et comparer les résultats avec le baseline. Observer comment les vulnérabilités créées apparaissent dans les rapports.

### Relancer Purple Knight

Exécutez Purple Knight et sauvegardez le rapport :

```powershell
Copy-Item "<chemin_rapport_PurpleKnight>\*.html" "C:\HAD\Reports\post_vulns_PK.html"
Copy-Item "<chemin_rapport_PurpleKnight>\*.json" "C:\HAD\Reports\post_vulns_PK.json"
```

### Points de comparaison à analyser

| Indicateur | Baseline | Après vulnérabilisation | Delta |
|------------|----------|------------------------|-------|
| Score global | ? | ? | ? |
| Comptes Kerberoastables | ? | ? | ? |
| Membres Domain Admins | ? | ? | ? |
| Comptes avec PW n'expirant pas | ? | ? | ? |

> 📝 **À noter dans votre rapport :** Identifiez précisément quels nouveaux findings sont apparus et lesquels correspondent aux vulnérabilités que vous venez de créer.

---

---

## Module 4 — Remédiation manuelle avec PowerShell

> **Objectif :** Corriger les vulnérabilités manuellement, sans outil tiers. C'est la méthode de référence que vous devez maîtriser avant d'automatiser.

### 📸 Action obligatoire — Snapshot pré-remédiation manuelle

```
Nom : snapshot_pre_remediation_manuelle_YYYY-MM-DD
```

---

### 4.1 — Remédiation : Retirer bdupont de Domain Admins

```powershell
# Retirer bdupont du groupe Domain Admins
Remove-ADGroupMember -Identity "Admins du domaine" -Members "bdupont" -Confirm:$false

# Vérification
Get-ADGroupMember -Identity "Admins du domaine" | Select-Object Name, SamAccountName
```

---

### 4.2 — Remédiation : Supprimer le SPN Kerberoastable

```powershell
# Retirer le SPN du compte svc-backup
Set-ADUser "svc-backup" `
    -ServicePrincipalNames @{Remove="MSSQLSvc/srv-backup.lab.local:1433"}

# Vérification
Get-ADUser -Identity "svc-backup" -Properties ServicePrincipalNames |
    Select-Object Name, ServicePrincipalNames
```

> 💡 **Alternative recommandée :** En production, si le service a réellement besoin d'un SPN, créez un **compte de service géré (gMSA)** dont le mot de passe est géré automatiquement par AD — rendant le Kerberoasting inutile.

---

### 4.3 — Remédiation : Forcer le renouvellement des mots de passe

```powershell
# Forcer la réinitialisation du mot de passe à la prochaine connexion
Set-ADUser -Identity "amartin" -ChangePasswordAtLogon $true
Set-ADUser -Identity "bdupont" -ChangePasswordAtLogon $true
Set-ADUser -Identity "svc-backup" -ChangePasswordAtLogon $true

# Désactiver le flag "mot de passe n'expire jamais" sur les comptes utilisateurs
Set-ADUser -Identity "amartin" -PasswordNeverExpires $false
Set-ADUser -Identity "bdupont" -PasswordNeverExpires $false
```

---

### 4.4 — Remédiation : Désactiver les comptes inutiles

```powershell
# Désactiver le compte de service (si plus nécessaire dans ce lab)
Disable-ADAccount -Identity "svc-backup"

# Vérification
Get-ADUser -Filter {
    SamAccountName -eq 'amartin' -or
    SamAccountName -eq 'bdupont' -or
    SamAccountName -eq 'svc-backup'
} -Properties PasswordNeverExpires, Enabled |
    Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires
```

---

### 4.5 — Bonne pratique : Politique de mots de passe renforcée (Fine-Grained Password Policy)

```powershell
# Créer une politique de mots de passe stricte pour les admins
New-ADFineGrainedPasswordPolicy `
    -Name "PSO_Admins" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "30.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -LockoutThreshold 5 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false

# Appliquer la politique au groupe Domain Admins
Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO_Admins" `
    -Subjects "Admins du domaine"

# Vérification
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, MinPasswordLength, Precedence
```

---

## Module 5 — Audit de validation post-remédiation

> **Objectif :** Démontrer que les remédiations ont été efficaces.

### Relancer Purple Knight (3ème audit)

```powershell
Copy-Item "<chemin_rapport_PurpleKnight>\*.html" "C:\HAD\Reports\post_remediation_manuelle_PK.html"
Copy-Item "<chemin_rapport_PurpleKnight>\*.json" "C:\HAD\Reports\post_remediation_manuelle_PK.json"
```

### Tableau de comparaison final (matin)

| Indicateur | Baseline | Post-vulns | Post-remédiation |
|------------|----------|------------|-----------------|
| Score global | ? | ? | ? |
| Kerberoastables | ? | ? | ? |
| Domain Admins | ? | ? | ? |
| PW n'expirant pas | ? | ? | ? |

> 📝 **À documenter :** Le score doit être revenu à un niveau proche ou supérieur au baseline. Si ce n'est pas le cas, identifiez les findings résiduels.

### 📸 Snapshot de fin de matinée

```
Nom : snapshot_post_remediation_manuelle_YYYY-MM-DD
```

---

---

# 🌆 APRÈS-MIDI — Automatisation avec HardenAD

---

## Module 6 — Introduction à HardenAD

> **Objectif :** Comprendre ce qu'est HardenAD, son architecture, et comment il s'intègre dans une démarche de sécurisation de l'Active Directory.

### Concept : Qu'est-ce que HardenAD ?

**HardenAD** est un framework open-source développé par Loïc Veirman (Semperis). Il implémente le modèle de sécurité **Tiering** (isolation des niveaux d'administration) recommandé par Microsoft. Il fonctionne via :

- Un fichier de configuration XML (`TasksSequence_HardenAD.xml`) qui liste les tâches disponibles
- Un script principal `HardenAD.ps1` qui exécute les tâches activées
- Une GUI optionnelle pour activer/désactiver les tâches visuellement
- Des logs détaillés dans `C:\HAD\Logs\`

### Architecture des tâches HardenAD

```
C:\HAD\
├── HardenAD.ps1                    ← Script principal
├── Configs\
│   └── TasksSequence_HardenAD.xml  ← Configuration des tâches (activer/désactiver)
├── Inputs\
│   ├── GroupPolicies\              ← GPOs à importer
│   └── ...
├── Logs\
│   ├── HardenAD-Results.csv        ← Résultats lisibles
│   ├── HardenAD-Results.log        ← Journal d'exécution
│   └── Debug\                      ← Logs détaillés
├── Tools\
│   └── Invoke-HardenADGUI\
│       └── Invoke-HardenADGui.ps1  ← Interface graphique
└── Reports\                        ← Vos rapports d'audit
```

### Le modèle de Tiering

```
┌──────────────────────────────────────────────────────────────────┐
│  Tier 0 : Contrôleurs de domaine, AD, PKI, ADFS                 │
│  → Comptes T0 uniquement — isolation totale                     │
├──────────────────────────────────────────────────────────────────┤
│  Tier 1 : Serveurs applicatifs, bases de données                │
│  → Comptes T1 — ne peuvent pas se connecter au T0              │
├──────────────────────────────────────────────────────────────────┤
│  Tier 2 : Postes de travail, utilisateurs                       │
│  → Comptes T2 — isolation totale des T0 et T1                  │
└──────────────────────────────────────────────────────────────────┘
```

> 💡 Ce modèle empêche qu'une compromission d'un poste utilisateur (T2) ne permette d'escalader vers les contrôleurs de domaine (T0).

---

---

## Module 7 — Exploration du dépôt HardenAD

> **Objectif :** Comprendre comment activer et désactiver des tâches spécifiques, avant de lancer la première exécution.

### 7.1 — Lancer l'interface graphique (GUI)

```powershell
cd C:\HAD
powershell -ExecutionPolicy Bypass -File .\Tools\Invoke-HardenADGUI\Invoke-HardenADGui.ps1
```

Dans la GUI :
- Chaque ligne représente une **tâche de durcissement**
- Une case cochée = tâche **activée** (sera exécutée au prochain run)
- Une case décochée = tâche **désactivée** (ignorée)
- Cliquez sur **Save** pour sauvegarder la configuration dans `TasksSequence_HardenAD.xml`

### 7.2 — Activer/désactiver des tâches via CLI

```powershell
cd C:\HAD

# Activer une tâche spécifique
.\HardenAD.ps1 -EnableTask 'Set Tier 0 Organizational Unit'

# Désactiver une tâche spécifique
.\HardenAD.ps1 -DisableTask 'Set Tier 0 Organizational Unit'

# Lister les tâches disponibles (lire le fichier XML)
[xml]$config = Get-Content "C:\HAD\Configs\TasksSequence_HardenAD.xml"
$config.Settings.Tasks.Task | Select-Object ID, Name, Status | Format-Table -AutoSize
```

### 7.3 — Explorer le fichier de configuration

```powershell
# Voir toutes les tâches activées
[xml]$config = Get-Content "C:\HAD\Configs\TasksSequence_HardenAD.xml"
$config.Settings.Tasks.Task |
    Where-Object { $_.Status -eq "Enabled" } |
    Select-Object ID, Name |
    Format-Table -AutoSize

# Voir toutes les tâches désactivées
$config.Settings.Tasks.Task |
    Where-Object { $_.Status -eq "Disabled" } |
    Select-Object ID, Name |
    Format-Table -AutoSize
```

> 📝 **À documenter :** Combien de tâches sont activées par défaut ? Quelles sont les catégories représentées (OU, GPO, ACL, LAPS...) ?

---

---

## Module 8 — Hardening par paliers avec HardenAD

> **Objectif :** Appliquer les remédiations HardenAD progressivement, en validant chaque étape avec un audit.

### Flux de travail (à respecter pour CHAQUE remédiation)

```
📸 Snapshot pré  →  🔧 Activer tâche(s)  →  ▶️ Lancer HardenAD
       ↓
✅ Validation PowerShell  →  🔍 Audit Purple Knight  →  📸 Snapshot post
       ↓
❌ Anomalie détectée ?  →  🔄 Rollback snapshot pré  →  📝 Documenter
```

---

### Remédiation A — Structure OU de Tiering *(Impact : Faible)*

#### Concept

La création d'une structure d'OU dédiée au modèle de tiering est la **fondation** de tout hardening AD. Elle permet d'isoler les comptes d'administration par niveau de confiance.

#### 📸 Snapshot pré

```
Nom : snapshot_pre_SetTreeOU_YYYY-MM-DD
```

#### Activation et exécution

```powershell
cd C:\HAD

# Option A : via CLI
.\HardenAD.ps1 -EnableTask 'Set Tier 0 Organizational Unit'
.\HardenAD.ps1 -EnableTask 'Set Tier 1 and 2 Organizational Unit'

# Lancer HardenAD
powershell -ExecutionPolicy Bypass -File .\HardenAD.ps1
```

**Option B : via GUI**
1. Lancer `Invoke-HardenADGui.ps1`
2. Cocher *"Set Tier 0 Organizational Unit"* et *"Set Tier 1 and 2 Organizational Unit"*
3. Cliquer **Save**
4. Lancer `.\HardenAD.ps1`

#### Validation

```powershell
# Vérifier la création des OU de Tiering
Get-ADOrganizationalUnit -Filter 'Name -like "Harden_*"' |
    Select-Object Name, DistinguishedName |
    Format-Table -AutoSize

# Sauvegarder la sortie
Get-ADOrganizationalUnit -Filter 'Name -like "Harden_*"' |
    Select-Object Name, DistinguishedName |
    Export-Csv "C:\HAD\Reports\SetTreeOU_after.csv" -NoTypeInformation
```

#### 📸 Snapshot post

```
Nom : snapshot_post_SetTreeOU_YYYY-MM-DD
```

#### Rollback (si nécessaire)

```
Hyper-V Manager → Clic droit VM → Checkpoints → Apply snapshot_pre_SetTreeOU_YYYY-MM-DD
```

---

### Remédiation B — Emplacement par défaut des nouveaux objets *(Impact : Faible)*

#### Concept

Par défaut, les nouveaux utilisateurs et ordinateurs créés dans AD atterrissent dans des conteneurs génériques (`CN=Users`, `CN=Computers`). Cette configuration rend la gestion des GPO et des délégations impossible. HardenAD redirige ces créations vers les OU du modèle de tiering.

#### 📸 Snapshot pré

```
Nom : snapshot_pre_DefaultLocation_YYYY-MM-DD
```

#### Activation et exécution

```powershell
cd C:\HAD
.\HardenAD.ps1 -EnableTask 'Default user location on creation'
.\HardenAD.ps1 -EnableTask 'Default computer location on creation'
powershell -ExecutionPolicy Bypass -File .\HardenAD.ps1
```

#### Validation

```powershell
# Créer un utilisateur test et vérifier son OU d'atterrissage
New-ADUser -Name "TP_TestUser_DefaultOU"

Get-ADUser -Filter { SamAccountName -eq 'TP_TestUser_DefaultOU' } |
    Select-Object Name, DistinguishedName

# Nettoyer après validation
Remove-ADUser -Identity "TP_TestUser_DefaultOU" -Confirm:$false
```

#### 📸 Snapshot post

```
Nom : snapshot_post_DefaultLocation_YYYY-MM-DD
```

---

### Remédiation C — Groupes d'administration dédiés *(Impact : Moyen)*

#### Concept

HardenAD crée des groupes d'administration spécifiques à chaque tier, conformément au modèle de délégation. Cela remplace l'usage direct des groupes natifs (`Domain Admins`, `Enterprise Admins`) qui sont trop larges.

#### 📸 Snapshot pré

```
Nom : snapshot_pre_AdminGroups_YYYY-MM-DD
```

#### État avant remédiation

```powershell
# Capturer l'état des groupes admins avant
Get-ADGroupMember -Identity "Admins du domaine" |
    Select-Object Name, SamAccountName |
    Export-Csv "C:\HAD\Reports\AdminGroups_before.csv" -NoTypeInformation
```

#### Activation et exécution

```powershell
cd C:\HAD
.\HardenAD.ps1 -EnableTask 'Create administration groups'
powershell -ExecutionPolicy Bypass -File .\HardenAD.ps1
```

#### Validation

```powershell
# Lister les nouveaux groupes créés par HardenAD
Get-ADGroup -Filter 'Name -like "Harden_*"' |
    Select-Object Name, GroupScope, GroupCategory |
    Format-Table -AutoSize

# Comparer les membres Domain Admins
Get-ADGroupMember -Identity "Admins du domaine" |
    Select-Object Name, SamAccountName |
    Export-Csv "C:\HAD\Reports\AdminGroups_after.csv" -NoTypeInformation
```

#### 📸 Snapshot post

```
Nom : snapshot_post_AdminGroups_YYYY-MM-DD
```

---

### Remédiation D — Import et liaison de GPOs durcies *(Impact : Moyen à Élevé)*

#### Concept

HardenAD fournit des **GPO préconfigurées** qui appliquent des paramètres de sécurité (restriction des droits de connexion, audit avancé, désactivation de protocoles obsolètes...). Ces GPO sont stockées dans `C:\HAD\Inputs\GroupPolicies\`.

> ⚠️ **Attention :** Les GPO ont un impact direct sur le comportement des machines du domaine. En TP, importez-les sur une **OU de test** uniquement, pas à la racine du domaine.

#### 📸 Snapshot pré

```
Nom : snapshot_pre_ImportGPO_YYYY-MM-DD
```

#### Activation et exécution

```powershell
cd C:\HAD
.\HardenAD.ps1 -EnableTask 'Prepare GPO files before GPO import'
.\HardenAD.ps1 -EnableTask 'Import new GPO or update existing ones'
powershell -ExecutionPolicy Bypass -File .\HardenAD.ps1
```

#### Validation

```powershell
# Vérifier les GPO importées par HardenAD
Get-GPO -All |
    Where-Object { $_.DisplayName -like "*HAD*" -or $_.DisplayName -like "*Harden*" } |
    Select-Object DisplayName, GpoStatus, CreationTime |
    Format-Table -AutoSize

# Vérifier les liens GPO
Get-GPInheritance -Target "DC=lab,DC=local" |
    Select-Object -ExpandProperty GpoLinks |
    Format-Table DisplayName, Enabled, Enforced
```

#### 📸 Snapshot post

```
Nom : snapshot_post_ImportGPO_YYYY-MM-DD
```

---

### Remédiation E — Modèle de délégation via ACEs *(Impact : Élevé)*

#### Concept

Cette remédiation applique le modèle de délégation au niveau des **ACLs Active Directory**. Elle contrôle qui peut modifier quels objets dans l'AD. C'est la remédiation la plus impactante — une erreur peut verrouiller des accès légitimes.

> ⚠️ **Manipulation à haut risque.**. Snapshot obligatoire.

#### 📸 Snapshot pré (CRITIQUE)

```
Nom : snapshot_pre_DelegationACEs_YYYY-MM-DD
```

#### État des ACLs avant remédiation

```powershell
# Capturer les ACLs d'une OU représentative (exemple)
$ou = "OU=Domain Controllers,DC=lab,DC=local"
$acl = Get-Acl "AD:\$ou"
$acl.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Export-Csv "C:\HAD\Reports\ACLs_before.csv" -NoTypeInformation
```

#### Activation et exécution

```powershell
cd C:\HAD
.\HardenAD.ps1 -EnableTask 'Enforce delegation model through ACEs'
powershell -ExecutionPolicy Bypass -File .\HardenAD.ps1
```

#### Validation

```powershell
# Comparer les ACLs après
$acl_after = Get-Acl "AD:\$ou"
$acl_after.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Export-Csv "C:\HAD\Reports\ACLs_after.csv" -NoTypeInformation

# Vérifier que les comptes privilegiés sont intacts
Get-ADGroupMember -Identity "Admins du domaine" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Administrateurs de l'entreprise" | Select-Object Name, SamAccountName
```

#### 📸 Snapshot post

```
Nom : snapshot_post_DelegationACEs_YYYY-MM-DD
```

---

### Récupérer les logs HardenAD après chaque run

```powershell
# Résultats synthétiques
Import-Csv "C:\HAD\Logs\HardenAD-Results.csv" | Format-Table -AutoSize

# Copier les logs vers votre répertoire de rapports
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
Copy-Item "C:\HAD\Logs\HardenAD-Results.csv" "C:\HAD\Reports\HAD_Results_$timestamp.csv"
Copy-Item "C:\HAD\Logs\HardenAD-Results.log" "C:\HAD\Reports\HAD_Results_$timestamp.log"
```

---

---

## Module 9 — Audit final et comparaison globale

> **Objectif :** Mesurer l'amélioration globale après toutes les remédiations HardenAD.

### Audit final Purple Knight

```powershell
# Lancer Purple Knight une dernière fois
Copy-Item "<chemin_rapport_PurpleKnight>\*.html" "C:\HAD\Reports\final_PK.html"
Copy-Item "<chemin_rapport_PurpleKnight>\*.json" "C:\HAD\Reports\final_PK.json"
```

### Tableau de synthèse finale

| Indicateur | Baseline | Post-vulns | Post-manuel | Post-HardenAD |
|------------|----------|------------|-------------|---------------|
| Score Purple Knight | ? | ? | ? | ? |
| Comptes Kerberoastables | ? | ? | ? | ? |
| Membres Domain Admins | ? | ? | ? | ? |
| OU de tiering présentes | Non | Non | Non | Oui |
| GPOs de durcissement | Non | Non | Non | ? |
| Modèle de délégation ACLs | Non | Non | Non | ? |

### 📸 Snapshot final

```
Nom : snapshot_final_post_hardenad_YYYY-MM-DD
```

---

---

## Module 10 — Rapport & Évaluation

### Structure du rapport à rendre

Le rapport doit être remis au format **PDF ou Markdown**, avec les sections suivantes :

---

#### Page de garde

- Noms et prénoms
- Date de la séance
- Nom de la VM
- Identifiant du snapshot initial

---

#### Résumé exécutif *(max 1 page)*

3 à 5 lignes résumant ce qui a été fait, les principaux findings, et l'amélioration globale mesurée.

---

#### Section 1 — Environnement

| Champ | Valeur |
|-------|--------|
| OS | |
| Rôle AD | |
| Nom du domaine | |
| Version HardenAD | |
| Compte utilisé | |
| Snapshot initial | |

---

#### Section 2 — Audit initial (baseline)

- Rapport Purple Knight baseline (joindre en annexe)
- Logs HardenAD baseline (joindre en annexe)
- **Top 10 des findings** classés par criticité

| # | Finding | Criticité | Catégorie |
|---|---------|-----------|-----------|
| 1 | | | |
| ... | | | |

---

#### Section 3 — Vulnérabilités créées (matin)

Pour chaque vulnérabilité :

| Vulnérabilité | Commande exacte | Finding PK associé | Risque |
|---------------|----------------|-------------------|--------|
| | | | |

---

#### Section 4 — Remédiations appliquées

Pour **chaque remédiation** (manuelle ou HardenAD) :

```
Remédiation : [Nom]
Snapshot pré : [Nom du snapshot]
Tâche HardenAD / Commande : [Copier-coller exact]
Résultat de validation : [Output PowerShell]
Snapshot post : [Nom du snapshot]
Finding PK corrigé : [Avant / Après]
```

---

#### Section 5 — Incidents & Rollbacks

*Si aucun rollback n'a été nécessaire, indiquer "RAS".*

| Action | Cause de l'incident | Snapshot restauré | Leçon apprise |
|--------|-------------------|-------------------|---------------|
| | | | |

---

#### Section 6 — Conclusion & Recommandations

- Synthèse de l'amélioration (score Purple Knight avant/après)
- 3 recommandations pour un environnement de production
- Limites identifiées du lab par rapport à la production

---

#### Annexes

- [ ] Rapport Purple Knight baseline (HTML)
- [ ] Rapport Purple Knight post-vulns (HTML)
- [ ] Rapport Purple Knight post-remédiation manuelle (HTML)
- [ ] Rapport Purple Knight final (HTML)
- [ ] Logs HardenAD (CSV + LOG)
- [ ] Captures d'écran des validations PowerShell

---

### Grille d'évaluation

| Critère | Points | Éléments évalués |
|---------|--------|-----------------|
| Respect des règles de sécurité & snapshots | 15 | Nommage correct, snapshot avant chaque action, rollback documenté si applicable |
| Qualité de l'audit initial et synthèse | 15 | Baseline PK exploitable, top 10 findings pertinents, inventaire complet |
| Pertinence et justification des risques sélectionnés | 20 | Choix argumenté, lien avec les findings, cohérence avec le modèle de tiering |
| Correctitude technique des commandes | 20 | Commandes exactes, syntaxe correcte, tâches HardenAD bien identifiées |
| Analyse avant/après et preuves | 20 | Comparaison chiffrée, outputs PowerShell joints, mesure d'amélioration |
| Présentation & clarté du rapport | 10 | Structure respectée, annexes complètes, lisibilité |
| **Total** | **100** | |

---

### Conseils finaux

> 💡 **Le but pédagogique est l'analyse, pas l'exécution.** Documenter *pourquoi* vous faites chaque action est plus important que d'exécuter le plus grand nombre de remédiations.

> ⚠️ **En cas d'erreur :** coupez l'activité, restaurez le snapshot, et joignez les logs d'erreur à votre rapport. Une restauration bien documentée vaut mieux qu'une exécution hasardeuse.

> 🔒 **Les remédiations intrusives** (modification du schéma AD, Forest/Domain Functional Level upgrade) ne doivent être réalisées uniquement après snapshot complet.

---

*Guide rédigé pour une séance de 7 heures — Windows Server 2022 — Purple Knight + HardenAD*
*Version 1.0 — Lab isolé uniquement*
