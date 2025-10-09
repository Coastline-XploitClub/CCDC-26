# Invitational 1

Lunar Looters From 2024/25 Season

## VPN
Netbird used for VPN. You must preinstall this on the system you are competing from:
- [Netbird](https://app.netbird.io/install)

## Proxmox
- We will have access to Proxmox backend to interact with the console of the VMs and start/restart VMs.
- No snapshotting or taking backups.
- Same view as our training environment

## Networking
- We will have direct access to the 192.168.220.0/24 subnet through our VPN.
- No need to access anything through 10.100.X.0/24 at the start
  - Services are still available at the 10.100.X.0/24 range and should be monitored

## Single Sign On Only!
- You will have ***1*** password to log in to the Authentik Dashboard.
- All links (scoring engine, proxmox, ticketing system, discord) are accessible through this one Dashboard

## Active Directory for all authentication
- This means password changes should be made on the Domain Controller and will affect all other VMs
- Doesn't mean there aren't local accounts that should be investigated, but count on root/admin accounts authenticating through AD.

 ## Environment VMs / Services
 - Balrog (Router) -- Alpine Linux
 - Charon (Docker Registry)
 - Brassknuckles (Mail)
 - Nix (Web server)
 - Kerberos (Active Directory) -- Windows
 - Cthulu (Sat Control) -- Windows
 - Tartarus (Rover Control)
 - Pandemonium (Gitea)
 - Donut (Load Balancer)
