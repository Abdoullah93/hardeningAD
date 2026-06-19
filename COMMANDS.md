## lien utile:
https://github.com/LoicVeirman/HardenAD/releases/tag/HardenAD-2.9.9v2
https://pierrezoltan.github.io/purpleknight.html

## 1. Utilisateurs standards 
```
New-ADUser -Name "Alice Martin" -SamAccountName "amartin" -AccountPassword (ConvertTo-SecureString "P@ssword1" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Bob Dupont" -SamAccountName "bdupont" -AccountPassword (ConvertTo-SecureString "Azerty123!" -AsPlainText -Force) -Enabled $true
```
## 2. Compte de service avec SPN (Kerberoastable) 
```
New-ADUser -Name "svc-backup" -SamAccountName "svc-backup" -AccountPassword (ConvertTo-SecureString "Backup2024" -AsPlainText -Force) -Enabled $true
Set-ADUser "svc-backup" -ServicePrincipalNames @{Add="MSSQLSvc/srv-backup.lab.local:1433"}
```
## 3. Mauvaise pratique : Ajout au groupe Domain Admins 
```
Add-ADGroupMember -Identity "Admins du domaine" -Members "bdupont"
```
## 4.Verification de creation 
Vérifier les utilisateurs créés et leurs propriétés de base :
```
Get-ADUser -Filter "SamAccountName -eq 'amartin' -or SamAccountName -eq 'bdupont' -or SamAccountName -eq 'svc-backup'"
```
Vérifier spécifiquement le compte de service et son SPN (Kerberoastable) :
```
Get-ADUser -Identity "svc-backup" -Properties ServicePrincipalNames | Select-Object Name, ServicePrincipalNames
```
Vérifier les membres du groupe "Admins du domaine" (pour valider l'élévation de bdupont) :
```
Get-ADGroupMember -Identity "Admins du domaine" | Select-Object Name, SamAccountName
```
