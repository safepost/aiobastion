import os
import argparse

parser = argparse.ArgumentParser(description='Helper for aiobastion.')
parser.add_argument('-c', '--config', help="Creates a standard config file to be used with aiobastion", required=True)
parser.add_argument('-a', '--aimconfig', help="Creates a AIM config file to be used with aiobastion", required=True)
parser.add_argument('-v', '--verbose', help="Afficher les informations détaillées", action='store_true')
args = parser.parse_args()

if args.config or args.aimconfig:
    label = input("Name of the Vault [Vault]: " or "Vault")

if args.config:
    # Connection Part
    username = input("Username []: ")
    if len(username) > 0:
        password = input("Password []: ")
    authtype = ""
    while authtype.lower() not in ("cyberark", "radius", "ldap", "windows"):
        authtype = input("Authentication (Cyberark, RADIUS, Ldap or Windows) [Cyberark]: " or "Cyberark")

    # PVWA Part
    pvwa_host = input("Address of PVWA, eg pvwa.acme.fr []: ")

if args.aimconfig:
    # AIM Part
    appid = input("AppID []: ")





    # defaults part


    with open(os.path.join(os.getcwd(), f"./config_{pvwa_host}.yml"), "w") as f:
        f.write(f"Label: {label}\n")
        f.write(f"Connection:\n")
        if len(username) > 0:
            f.write(f"\tUsername: {username}")


