#!/usr/bin/env python3
import subprocess
import os
import re
import requests

# Kleuren
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
RED = '\033[1;31m'
RESET = '\033[0m'

# Zimbra-server URL (vervang dit door de juiste URL van jouw server)
ZIMBRA_URL = "https://webmail.my-zimbra.be/"

def get_zimbra_config(key):
    """Haal de Zimbra configuratie op voor een specifieke sleutel."""
    try:
        result = subprocess.run(
            ['sudo', '-u', 'zimbra', '/opt/zimbra/bin/zmprov', 'gcf', key],  # Pad naar zmprov
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        output = result.stdout.decode('utf-8').strip().split("\n")
        if len(output) > 1:
            return output[1].strip()  # Return the actual value
        else:
            return None  # Return None if the value is not found
    except subprocess.CalledProcessError as e:
        print(f"Fout bij het ophalen van configuratie voor {key}: {e.stderr.decode('utf-8')}")
        return None

def get_cos_list():
    """Haal de lijst van COS'en op."""
    try:
        result = subprocess.run(
            ['sudo', '-u', 'zimbra', '/opt/zimbra/bin/zmprov', 'gac'],  # Haal alle COS'en op
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        cos_list = result.stdout.decode('utf-8').strip().split("\n")
        return cos_list
    except subprocess.CalledProcessError as e:
        print(f"Fout bij het ophalen van COS lijst: {e.stderr.decode('utf-8')}")
        return []

def check_tls_protocols():
    """Controleer TLS protocollen."""
    tls_protocols = get_zimbra_config('zimbraReverseProxySSLProtocols')
    if tls_protocols:
        if 'TLSv1.2' in tls_protocols or 'TLSv1.3' in tls_protocols:
            return f"{GREEN}[+] TLS Protocols: OK ({tls_protocols}){RESET}"
        else:
            return f"{RED}[-] TLS Protocols: Onveilige protocollen actief ({tls_protocols}){RESET}"
    return f"{RED}[-] TLS Protocols: Kon waarde niet ophalen{RESET}"

def check_ssl_ciphers():
    """Controleer SSL ciphers."""
    ciphers = get_zimbra_config('zimbraReverseProxySSLCiphers')
    if ciphers:
        return f"{GREEN}[+] SSL Ciphers: Geconfigureerd{RESET}"
    return f"{RED}[-] SSL Ciphers: Niet opgehaald{RESET}"

def check_timeouts():
    """Controleer algemene timeouts."""
    admin_timeout = get_zimbra_config('zimbraAdminConsoleSessionTimeout')
    mail_timeout = get_zimbra_config('zimbraMailIdleSessionTimeout')
    web_timeout = get_zimbra_config('zimbraWebClientSessionTimeout')

    timeout_messages = []

    if admin_timeout:
        timeout_messages.append(f"{GREEN}[+] Admin Console Timeout: {admin_timeout}{RESET}")
    else:
        timeout_messages.append(f"{RED}[-] Admin Console Timeout: Kon waarde niet bepalen{RESET}")

    if mail_timeout:
        timeout_messages.append(f"{GREEN}[+] Mail Idle Timeout: {mail_timeout}{RESET}")
    else:
        timeout_messages.append(f"{RED}[-] Mail Idle Timeout: Kon waarde niet bepalen{RESET}")

    if web_timeout:
        timeout_messages.append(f"{GREEN}[+] Webclient Session Timeout: {web_timeout}{RESET}")
    else:
        timeout_messages.append(f"{RED}[-] Webclient Timeout: Kon waarde niet bepalen{RESET}")

    return '\n'.join(timeout_messages)

def check_admin_console():
    """Controleer of de Admin Console luistert op poort 7071."""
    result = subprocess.run(
        ['ss', '-tln'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    if ':7071' in result.stdout.decode('utf-8'):
        return f"{YELLOW}[*] Admin Console: LUISTERT op poort 7071 — controleer firewall!{RESET}"
    return f"{GREEN}[+] Admin Console: niet publiek beschikbaar{RESET}"

def check_nginx_log():
    """Controleer of het Nginx logbestand aanwezig is."""
    nginx_log = "/opt/zimbra/log_
