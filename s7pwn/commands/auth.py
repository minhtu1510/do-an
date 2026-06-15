"""
Authentication command for S7 PLCs
"""

from __future__ import annotations
from typing import List
from s7pwn.ext.s7_auth import (
    S7AuthClient, quick_auth_check, get_common_passwords,
    ProtectionLevel, AccessLevel
)
from s7pwn.runtime import get_current_target, set_auth_session
import getpass


def auth(args: List[str]) -> None:
    """
    S7 PLC Authentication Management

    Usage:
        auth --help                    # Show this help
        auth check                     # Check protection level
        auth login                     # Login with password (interactive)
        auth login <password>          # Login with password
        auth bruteforce               # Brute force with common passwords
        auth bruteforce <wordlist>    # Brute force with custom wordlist

    Examples:
        auth check
        auth login
        auth login mypassword123
        auth bruteforce
        auth bruteforce /path/to/wordlist.txt
    """

    if len(args) == 0 or (len(args) > 0 and args[0] == '--help'):
        print(auth.__doc__)
        return

    target = get_current_target()
    if not target:
        print("[!] No target selected. Use 'select <n>' or 'set_target' first.")
        return

    ip = target['ip']
    rack = target.get('rack', 0)
    slot = target.get('slot', 1)

    command = args[0].lower()

    # === CHECK PROTECTION LEVEL ===
    if command == 'check':
        print(f"\n{'='*60}")
        print(f"S7 PROTECTION CHECK")
        print(f"{'='*60}")
        print(f"Target: {ip} (Rack {rack}, Slot {slot})")
        print(f"{'='*60}\n")

        result = quick_auth_check(ip, rack, slot)

        if not result['connected']:
            print("[!] Connection failed")
            print("    - Check IP address and network connectivity")
            print("    - Verify Rack/Slot configuration")
            print("    - Ensure PLC is online")
            return

        print("[+] Connection successful\n")

        # Protection Level
        print(f"Protection Level: ", end="")
        if result['protection_level']:
            level = result['protection_level']
            if level == 'NO_PROTECTION':
                print("🟢 No Protection")
                print("    → Full access without password")
            elif level == 'WRITE_PROTECTION':
                print("🟡 Write Protection")
                print("    → Read allowed, write requires password")
            elif level == 'READ_WRITE_PROTECTION':
                print("🟠 Read/Write Protection")
                print("    → Password required for read and write")
            elif level == 'COMPLETE_PROTECTION':
                print("🔴 Complete Protection")
                print("    → Full password protection active")
        else:
            print("Unknown")

        print()

        # Access Level
        print(f"Current Access Level: ", end="")
        if result['access_level']:
            access = result['access_level']
            if access == 'NO_ACCESS':
                print("🔒 No Access")
                print("    → Authentication required")
            elif access == 'READ_ACCESS':
                print("📖 Read Access")
                print("    → Can read, cannot write")
            elif access == 'HMI_ACCESS':
                print("🖥️  HMI Access")
                print("    → Limited control operations")
            elif access == 'FULL_ACCESS':
                print("🔓 Full Access")
                print("    → Complete read/write access")
        else:
            print("Unknown")

        print()

        # Recommendations
        if result['requires_password']:
            print("⚠️  Password Required")
            print("    Use 'auth login <password>' to authenticate")
            print("    Or 'auth bruteforce' for password testing (authorized only)")
        else:
            print("✅ No password required")
            print("    You can proceed with read/write operations")

        print(f"\n{'='*60}\n")

    # === LOGIN WITH PASSWORD ===
    elif command == 'login':
        if len(args) < 2:
            # Interactive password input
            password = getpass.getpass("Enter PLC password: ")
        else:
            password = args[1]

        print(f"\n[*] Authenticating to {ip}...")

        client = S7AuthClient(ip, rack, slot)

        if not client.connect():
            print("[!] Connection failed")
            return

        print("[+] Connected")

        if client.authenticate_with_password(password):
            print("[+] ✅ Authentication successful!")
            print(f"[+] Access granted with password: {'*' * len(password)}")

            # Test access level
            access = client.test_access()
            print(f"[+] Access Level: {access.name}")

            # Store in runtime for future commands
            set_auth_session({
                'ip': ip,
                'rack': rack,
                'slot': slot,
                'password': password,
                'authenticated': True,
                'access_level': access.name
            })

            print("\n[*] Session saved. Commands will use authenticated connection.")

        else:
            print("[!] ❌ Authentication failed")
            print("    - Verify password is correct")
            print("    - Check PLC access control settings in TIA Portal")
            print("    - Ensure PLC allows password authentication")

        client.disconnect()

    # === BRUTE FORCE ===
    elif command == 'bruteforce':
        print("\n" + "="*60)
        print("⚠️  PASSWORD BRUTE FORCE - AUTHORIZED TESTING ONLY")
        print("="*60)
        print("WARNING: Only use on systems you own or have permission to test")
        print("="*60 + "\n")

        confirm = input("Continue? (yes/no): ").lower()
        if confirm != 'yes':
            print("Aborted.")
            return

        # Load password list
        if len(args) > 1:
            wordlist_path = args[1]
            try:
                with open(wordlist_path, 'r') as f:
                    password_list = [line.strip() for line in f if line.strip()]
                print(f"[*] Loaded {len(password_list)} passwords from {wordlist_path}")
            except Exception as e:
                print(f"[!] Error loading wordlist: {e}")
                return
        else:
            password_list = get_common_passwords()
            print(f"[*] Using {len(password_list)} common passwords")

        print(f"[*] Target: {ip} (Rack {rack}, Slot {slot})")
        print(f"[*] Max attempts: {len(password_list)}")
        print()

        # Perform brute force
        client = S7AuthClient(ip, rack, slot)
        valid_password = client.brute_force_password(password_list)

        if valid_password:
            print(f"\n{'='*60}")
            print("✅ SUCCESS!")
            print(f"{'='*60}")
            print(f"Valid password: {valid_password}")
            print(f"{'='*60}\n")

            # Store in session
            set_auth_session({
                'ip': ip,
                'rack': rack,
                'slot': slot,
                'password': valid_password,
                'authenticated': True,
                'access_level': 'UNKNOWN'
            })

            print("[*] Session saved. Use 'auth check' to verify access level.")
        else:
            print(f"\n[!] Password not found")
            print("    - Try a different wordlist")
            print("    - Check if PLC has lockout after failed attempts")
            print("    - Verify PLC uses password authentication")

    else:
        print(f"[!] Unknown command: {command}")
        print("Use 'auth --help' for usage information")
