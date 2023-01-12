if __name__ == "__main__":
    # TODO : Detect existing file name
    label = input("Name of the Vault [Vault]: " or "Vault")
    username = input("Username []: ")
    password = input("Password []: ")
    authtype = input("Authentication (Cyberark, RADIUS, Ldap...) [Cyberark]: " or "Cyberark")
    pvwa_host = input("Address of PVWA, eg pvwa.acme.fr []: ")
    with open(f"config_{pvwa_host}.yml", "w") as f:
        f.write(f"Label: {label}\n")

