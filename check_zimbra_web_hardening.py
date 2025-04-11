# replace zimbra_url = "https://webmail.zimbra-url/" with your own web url 
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
    """Controleer timeouts."""
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
    nginx_log = "/opt/zimbra/log/nginx.access.log"
    if os.path.isfile(nginx_log):
        return f"{GREEN}[+] Nginx Log: Aanwezig ({nginx_log}){RESET}"
    return f"{RED}[-] Nginx Log: Niet gevonden{RESET}"

def check_security_headers():
    """Controleer of security headers zijn ingesteld."""
    custom_template = "/opt/zimbra/conf/nginx/templates/custom/nginx.conf.web.https.default.template"
    if os.path.isfile(custom_template):
        with open(custom_template, 'r') as f:
            content = f.read()
            if "add_header X-Content-Type-Options" in content:
                return f"{GREEN}[+] Security Headers: Ingesteld in custom template{RESET}"
            return f"{RED}[-] Security Headers: Geen relevante headers in custom template{RESET}"
    return f"{YELLOW}[*] Security Headers: Geen custom nginx template actief{RESET}"

def check_server_version_header():
    """Controleer of de Zimbra-versie niet zichtbaar is in de Server-header."""
    zimbra_url = "https://webmail.zimbra-url/"  # Vervang met je Zimbra-server URL
    try:
        response = requests.get(zimbra_url)  # Zet verify=False als je een zelf-ondertekend certificaat gebruikt
        server_header = response.headers.get('Server', '')
        if 'Zimbra' in server_header:
            return f"{RED}[-] Zimbra versie is zichtbaar in de Server-header: {server_header}{RESET}"
        return f"{GREEN}[+] Zimbra versie is verborgen in de Server-header{RESET}"
    except requests.exceptions.RequestException as e:
        return f"{RED}[-] Fout bij het verbinden met Zimbra-server: {e}{RESET}"

def main():
    print(f"{YELLOW}=== Zimbra Web Access Hardening Check ==={RESET}")

    # TLS Protocols check
    print(check_tls_protocols())

    # SSL Ciphers check
    print(check_ssl_ciphers())

    # Timeouts check
    print(check_timeouts())

    # Admin Console check
    print(check_admin_console())

    # Nginx log check
    print(check_nginx_log())

    # Security headers check
    print(check_security_headers())

    # Server version header check
    print(check_server_version_header())

    print(f"{YELLOW}=== Controle afgerond ==={RESET}")

if __name__ == "__main__":
    main()
