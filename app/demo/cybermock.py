"""Demo / test inventory for "Cybermock Solution GmbH".

Cybermock is a FICTIONAL company used for training (see the Cybermock Information Pack and
the Cloud Security & Compliance Audit). The inventory follows those documents:

  * on-premises Active Directory cybermock.local synced to Microsoft Entra ID cybermock.io
  * ~40 Windows 10/11 laptops and desktops, about half used remotely / at customer sites
  * domain controller, file/print server and HR system on-premises, internal SIEM
  * Microsoft Azure hosting customer-facing web apps and internal tools, incl. the storage
    accounts cminsights544g9v (anonymous blob access) and labscripts45thai (permanent owners)
    named in the audit

All IP addresses are private (RFC 1918) or documentation ranges (RFC 5737), all host names use
the fictional cybermock.* domains - nothing here points at a real system.

Cloud specifics (provider, subscription, resource group, region, resource type) are stored as
tags until the asset model gets dedicated cloud fields.
"""
from __future__ import annotations

DEMO_TAG = "demo:cybermock"

IT = "IT Operations (T. Wilson)"
SOC = "SOC (F. Wagner)"
ENG = "Engineering"
HR = "HR"
FIN = "Finance (S. Hartmann)"
CISO = "CISO Office (A. Schreiber)"


def _azure(subscription: str, resource_group: str, resource_type: str,
           region: str = "germanywestcentral") -> list[str]:
    return ["cloud", "provider:azure", f"subscription:{subscription}", f"rg:{resource_group}",
            f"region:{region}", f"azure:{resource_type}"]


ON_PREM: list[dict] = [
    dict(name="CM-DC01", asset_type="server", environment="production", criticality="critical",
         internet_facing="no", ip_address="10.10.10.10", hostname="cm-dc01.cybermock.local", owner=IT,
         description="Primary Active Directory domain controller for cybermock.local (DNS, Kerberos, GPO). "
                     "Audit finding: weak default password policy, lockout disabled.",
         tags=["on-prem", "identity", "active-directory", "windows-server-2019", "finding:ad-password-policy"]),
    dict(name="CM-AADC01", asset_type="server", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.10.12", hostname="cm-aadc01.cybermock.local", owner=IT,
         description="Microsoft Entra Connect server synchronising cybermock.local to Entra ID (cybermock.io).",
         tags=["on-prem", "identity", "entra-connect", "windows-server-2022"]),
    dict(name="CM-FS01", asset_type="server", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.10.20", hostname="cm-fs01.cybermock.local", owner=IT,
         description="File and print server (department shares, customer project folders, print queues).",
         tags=["on-prem", "file-server", "print-server", "windows-server-2019", "contains:customer-data"]),
    dict(name="CM-HR01", asset_type="server", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.10.30", hostname="cm-hr01.cybermock.local", owner=HR,
         description="Host of the internal HR system (employee records, payroll exports).",
         tags=["on-prem", "hr", "windows-server-2019", "contains:employee-data", "gdpr"]),
    dict(name="HR Portal", asset_type="web_application", environment="production", criticality="high",
         internet_facing="no", hostname="hr.cybermock.local", owner=HR,
         description="Internal HR web application running on CM-HR01; reachable from the office network and VPN only.",
         tags=["on-prem", "hr", "contains:employee-data", "gdpr"]),
    dict(name="HR Database", asset_type="database", environment="production", criticality="critical",
         internet_facing="no", ip_address="10.10.10.31", hostname="cm-hrdb01.cybermock.local", owner=HR,
         description="SQL Server database behind the HR Portal (personal data of ~45 employees).",
         tags=["on-prem", "hr", "sql-server", "contains:employee-data", "gdpr"]),
    dict(name="CM-SIEM01", asset_type="server", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.20.10", hostname="cm-siem01.cybermock.local", owner=SOC,
         description="Internal SIEM collecting logs for compliance; currently not actively monitored for threats.",
         tags=["on-prem", "security", "siem", "logging", "linux"]),
    dict(name="CM-BKP01", asset_type="server", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.20.20", hostname="cm-bkp01.cybermock.local", owner=IT,
         description="On-premises backup server (Veeam) for DC, file server and HR system. "
                     "Audit finding: incomplete backup coverage.",
         tags=["on-prem", "backup", "windows-server-2022", "finding:backup-coverage"]),
    dict(name="CM-FW01", asset_type="network_device", environment="production", criticality="critical",
         internet_facing="yes", ip_address="203.0.113.10", hostname="fw01.cybermock.io", owner=IT,
         description="Perimeter firewall of the office (WAN edge, NAT, site-to-site VPN to Azure).",
         tags=["on-prem", "network", "firewall", "perimeter"]),
    dict(name="CM-VPN01", asset_type="network_device", environment="production", criticality="critical",
         internet_facing="yes", ip_address="203.0.113.11", hostname="vpn.cybermock.io", owner=IT,
         description="Remote-access VPN gateway used by remote and travelling staff (Consulting, Sales).",
         tags=["on-prem", "network", "vpn", "remote-access"]),
    dict(name="CM-SW-CORE01", asset_type="network_device", environment="production", criticality="high",
         internet_facing="no", ip_address="10.10.0.2", hostname="cm-sw-core01.cybermock.local", owner=IT,
         description="Core switch of the office network (server, client and management VLANs).",
         tags=["on-prem", "network", "switch"]),
    dict(name="CM-WLC01", asset_type="network_device", environment="production", criticality="medium",
         internet_facing="no", ip_address="10.10.0.5", hostname="cm-wlc01.cybermock.local", owner=IT,
         description="Wireless LAN controller (staff and guest Wi-Fi).",
         tags=["on-prem", "network", "wifi"]),
    dict(name="CM-PRN-OFFICE01", asset_type="other", environment="production", criticality="low",
         internet_facing="no", ip_address="10.10.30.50", hostname="cm-prn01.cybermock.local", owner=IT,
         description="Office multifunction printer, managed via CM-FS01.",
         tags=["on-prem", "printer", "iot"]),
]

CLOUD: list[dict] = [
    dict(name="Entra ID tenant cybermock.io", asset_type="cloud_resource", environment="production",
         criticality="critical", internet_facing="yes", hostname="login.cybermock.io", owner=IT,
         description="Microsoft Entra ID tenant (cloud identity, synced from cybermock.local). "
                     "Audit finding: permanent privileged role assignments, PIM not enforced.",
         tags=["cloud", "provider:azure", "identity", "entra-id", "azure:tenant", "finding:pim-gaps"]),
    dict(name="Microsoft 365 / Exchange Online", asset_type="cloud_resource", environment="production",
         criticality="high", internet_facing="yes", hostname="mail.cybermock.io", owner=IT,
         description="E-mail and collaboration (incl. the shared mailbox that receives security alerts).",
         tags=["cloud", "provider:microsoft", "saas", "email", "m365"]),
    dict(name="app-cm-customerportal-prod", asset_type="web_application", environment="production",
         criticality="critical", internet_facing="yes", ip_address="198.51.100.20",
         hostname="portal.cybermock.io", owner=ENG,
         description="Customer-facing portal for managed security customers (reports, tickets). Azure App Service "
                     "/subscriptions/cm-prod/resourceGroups/rg-cm-prod-web/providers/Microsoft.Web/sites/"
                     "app-cm-customerportal-prod",
         tags=_azure("cm-prod", "rg-cm-prod-web", "app-service") + ["customer-facing", "contains:customer-data"]),
    dict(name="app-cm-customerportal-stg", asset_type="web_application", environment="staging",
         criticality="medium", internet_facing="yes", ip_address="198.51.100.21",
         hostname="portal-stg.cybermock.io", owner=ENG,
         description="Staging slot of the customer portal; uses anonymised test data.",
         tags=_azure("cm-prod", "rg-cm-prod-web", "app-service") + ["customer-facing"]),
    dict(name="app-cm-socdashboard-prod", asset_type="web_application", environment="production",
         criticality="critical", internet_facing="yes", ip_address="198.51.100.22",
         hostname="soc.cybermock.io", owner=SOC,
         description="Managed detection dashboard for customers (alerts, incident status).",
         tags=_azure("cm-prod", "rg-cm-prod-web", "app-service") + ["customer-facing", "contains:customer-data"]),
    dict(name="agw-cm-prod", asset_type="network_device", environment="production", criticality="critical",
         internet_facing="yes", ip_address="198.51.100.10", hostname="agw.cybermock.io", owner=IT,
         description="Azure Application Gateway with WAF in front of the customer-facing apps.",
         tags=_azure("cm-prod", "rg-cm-prod-network", "application-gateway") + ["waf", "perimeter"]),
    dict(name="vnet-cm-prod", asset_type="cloud_resource", environment="production", criticality="high",
         internet_facing="no", owner=IT,
         description="Production virtual network 10.20.0.0/16 (web, data, aks subnets); "
                     "site-to-site VPN to the office (CM-FW01).",
         tags=_azure("cm-prod", "rg-cm-prod-network", "virtual-network") + ["network", "cidr:10.20.0.0/16"]),
    dict(name="sql-cm-prod", asset_type="database", environment="production", criticality="critical",
         internet_facing="no", ip_address="10.20.2.4", hostname="sql-cm-prod.database.windows.net", owner=ENG,
         description="Azure SQL Database for the customer portal and SOC dashboard (private endpoint).",
         tags=_azure("cm-prod", "rg-cm-prod-data", "sql-database") + ["contains:customer-data", "gdpr"]),
    dict(name="cminsights544g9v", asset_type="cloud_resource", environment="production", criticality="high",
         internet_facing="yes", hostname="cminsights544g9v.blob.core.windows.net", owner=SOC,
         description="Storage account for customer insight exports. Audit finding (ISO 27002 8.3): anonymous blob "
                     "access enabled and public network access set to 'All networks'.",
         tags=_azure("cm-prod", "rg-cm-prod-data", "storage-account")
              + ["contains:customer-data", "finding:anonymous-blob-access"]),
    dict(name="labscripts45thai", asset_type="cloud_resource", environment="test", criticality="medium",
         internet_facing="yes", hostname="labscripts45thai.blob.core.windows.net", owner=ENG,
         description="Storage account for lab scripts. Audit finding (ISO 27002 8.2/8.3): six permanent Owners, an "
                     "orphaned identity with Reader rights, permissions inherited from subscription level.",
         tags=_azure("cm-lab", "rg-cm-lab", "storage-account", "westeurope") + ["lab", "finding:permanent-owners",
                                                                             "finding:orphaned-identity"]),
    dict(name="kv-cm-prod", asset_type="cloud_resource", environment="production", criticality="critical",
         internet_facing="no", hostname="kv-cm-prod.vault.azure.net", owner=IT,
         description="Azure Key Vault holding application secrets and certificates for production.",
         tags=_azure("cm-prod", "rg-cm-prod-security", "key-vault") + ["secrets"]),
    dict(name="aks-cm-internal", asset_type="container", environment="production", criticality="high",
         internet_facing="no", ip_address="10.20.8.4", hostname="aks-cm-internal.privatelink.germanywestcentral.azmk8s.io",
         owner=ENG,
         description="Private AKS cluster running internal tools (ticket sync, report generator).",
         tags=_azure("cm-prod", "rg-cm-prod-aks", "aks") + ["kubernetes", "internal-tools"]),
    dict(name="acrcmprod", asset_type="cloud_resource", environment="production", criticality="high",
         internet_facing="yes", hostname="acrcmprod.azurecr.io", owner=ENG,
         description="Azure Container Registry for images deployed to aks-cm-internal and the App Services.",
         tags=_azure("cm-prod", "rg-cm-prod-aks", "container-registry") + ["supply-chain"]),
    dict(name="func-cm-ticketsync", asset_type="cloud_resource", environment="production", criticality="medium",
         internet_facing="yes", hostname="func-cm-ticketsync.azurewebsites.net", owner=SOC,
         description="Azure Function synchronising customer tickets between the SOC dashboard and the ticket system.",
         tags=_azure("cm-prod", "rg-cm-prod-web", "function-app") + ["integration"]),
    dict(name="log-cm-prod", asset_type="cloud_resource", environment="production", criticality="high",
         internet_facing="no", owner=SOC,
         description="Log Analytics workspace for Azure diagnostics. Audit finding: threat detection (Defender for "
                     "Cloud plans) not enabled.",
         tags=_azure("cm-prod", "rg-cm-prod-security", "log-analytics") + ["logging", "finding:threat-detection"]),
    dict(name="rsv-cm-prod", asset_type="cloud_resource", environment="production", criticality="high",
         internet_facing="no", owner=IT,
         description="Recovery Services vault; covers sql-cm-prod but not the storage accounts or AKS volumes "
                     "(audit finding: incomplete backup coverage).",
         tags=_azure("cm-prod", "rg-cm-prod-security", "recovery-vault") + ["backup", "finding:backup-coverage"]),
    dict(name="bas-cm-prod", asset_type="network_device", environment="production", criticality="high",
         internet_facing="yes", ip_address="198.51.100.30", owner=IT,
         description="Azure Bastion for administrative RDP/SSH access to Azure VMs.",
         tags=_azure("cm-prod", "rg-cm-prod-network", "bastion") + ["admin-access"]),
    dict(name="vm-cm-build01", asset_type="virtual_machine", environment="development", criticality="medium",
         internet_facing="no", ip_address="10.30.1.10", hostname="vm-cm-build01.cybermock.local", owner=ENG,
         description="Build agent for the engineering CI pipelines (Ubuntu 22.04).",
         tags=_azure("cm-dev", "rg-cm-dev", "virtual-machine", "westeurope") + ["ci", "linux"]),
    dict(name="vm-cm-lab-dc01", asset_type="virtual_machine", environment="test", criticality="low",
         internet_facing="no", ip_address="10.40.0.4", hostname="lab-dc01.lab.cybermock.local", owner=SOC,
         description="Isolated lab domain controller used for consulting demos and training.",
         tags=_azure("cm-lab", "rg-cm-lab", "virtual-machine", "westeurope") + ["lab", "windows-server-2022"]),
]

# ~40 endpoints as described in the Information Pack (Windows 10/11, many used remotely).
_ENDPOINT_PLAN = [
    # department, count, asset_type, remote/travelling, owner
    ("Consulting", 12, "laptop", True, "Consulting"),
    ("Sales", 6, "laptop", True, "Sales"),
    ("SOC", 6, "workstation", False, SOC),
    ("Engineering", 6, "laptop", True, ENG),
    ("Management", 2, "laptop", True, "Management (K. Zimmermann)"),
    ("Finance", 2, "workstation", False, FIN),
    ("HR", 2, "workstation", False, HR),
    ("Legal", 1, "laptop", False, "Legal (C. Roth)"),
    ("IT", 2, "laptop", False, IT),
    ("CISO", 1, "laptop", True, CISO),
]


def _endpoints() -> list[dict]:
    assets, n = [], 0
    for dept, count, kind, remote, owner in _ENDPOINT_PLAN:
        for i in range(1, count + 1):
            n += 1
            prefix = "LT" if kind == "laptop" else "WS"
            name = f"CM-{prefix}-{n:03d}"
            os_tag = "windows-10" if n % 4 == 0 else "windows-11"
            tags = ["endpoint", os_tag, f"dept:{dept.lower()}", "defender-av"]
            if remote:
                tags.append("remote-worker")
            assets.append(dict(
                name=name, asset_type=kind, environment="production",
                criticality="high" if dept in ("Management", "Finance", "HR", "SOC", "CISO") else "medium",
                internet_facing="unknown" if remote else "no",
                ip_address=None if remote else f"10.10.40.{100 + n}",
                hostname=f"{name.lower()}.cybermock.local", owner=f"{owner} - user {i:02d}",
                description=f"{'Laptop' if kind == 'laptop' else 'Desktop'} of a {dept} employee. Windows Defender "
                            f"Antivirus only (no EDR).{' Frequently used off-network at customer sites.' if remote else ''}",
                tags=tags))
    return assets


# Laptop of the senior consultant affected by INC-2031: wiped and reissued -> old record inactive.
INACTIVE: list[dict] = [
    dict(name="CM-LT-INC2031", asset_type="laptop", environment="production", criticality="medium",
         internet_facing="unknown", hostname="cm-lt-inc2031.cybermock.local", owner="Consulting - senior consultant",
         description="Laptop affected by incident INC-2031 (malicious attachment, unusual outbound traffic, no EDR "
                     "alert). Wiped and reissued; record kept for incident traceability.",
         tags=["endpoint", "windows-11", "dept:consulting", "remote-worker", "incident:inc-2031"]),
]


def inventory() -> list[dict]:
    """Complete demo inventory; every asset carries the DEMO_TAG."""
    items = ON_PREM + CLOUD + _endpoints() + INACTIVE
    for item in items:
        item["tags"] = list(dict.fromkeys([DEMO_TAG] + item.get("tags", [])))
        item.setdefault("ip_address", None)
    return items


INACTIVE_NAMES = {a["name"] for a in INACTIVE}
