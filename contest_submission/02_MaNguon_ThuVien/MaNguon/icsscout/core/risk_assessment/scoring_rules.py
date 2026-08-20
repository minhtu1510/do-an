"""
Scoring Rules for Risk Assessment

Defines scoring algorithms, weights, and deduction rules
"""

from typing import Dict, List, Tuple
from datetime import datetime


class ScoringRules:
    """Risk scoring rules and algorithms"""

    # Category weights (must sum to 1.0)
    CATEGORY_WEIGHTS = {
        "network": 0.25,
        "device": 0.30,
        "vulnerability": 0.25,
        "compliance": 0.20
    }

    # Device criticality multipliers
    CRITICALITY_MULTIPLIERS = {
        "Safety PLC": 1.5,
        "Emergency Shutdown": 1.5,
        "SCADA Server": 1.3,
        "Historian": 1.3,
        "Production PLC": 1.2,
        "PLC": 1.2,
        "HMI": 1.1,
        "Engineering Workstation": 1.1,
        "Switch": 1.0,
        "Router": 1.0,
        "RTU": 1.0,
        "I/O Module": 0.9,
        "Field Device": 0.9,
        "Unknown": 1.0
    }

    # Network security deductions
    NETWORK_DEDUCTIONS = {
        "no_segmentation": 40,
        "no_it_ot_separation": 30,
        "internet_exposed": 20,  # per device
        "insecure_protocol": 15,  # per protocol
        "unnecessary_port": 10,   # per port
        "no_firewall": 25,
        "broadcast_unrestricted": 15,
        "no_vlan": 20,
        "weak_network_auth": 15
    }

    # Device security deductions
    DEVICE_DEDUCTIONS = {
        "protection_level_0": 50,
        "protection_level_1": 30,
        "protection_level_2": 15,
        "default_credentials": 40,
        "weak_password": 25,
        "firmware_age_3_5_years": 25,
        "firmware_age_5_plus_years": 40,
        "debug_service_enabled": 20,
        "telnet_enabled": 30,
        "ftp_enabled": 20,
        "http_no_https": 15,
        "snmp_v1_v2": 20,
        "no_authentication": 45,
        "unnecessary_service": 10  # per service
    }

    # Vulnerability deductions
    VULNERABILITY_DEDUCTIONS = {
        "critical_cve_with_exploit": 40,  # per CVE
        "critical_cve_no_exploit": 30,
        "high_cve_with_exploit": 20,
        "high_cve_no_exploit": 15,
        "medium_cve": 10,
        "low_cve": 5,
        "info_cve": 2
    }

    # Compliance scoring (positive points, out of 100)
    COMPLIANCE_POINTS = {
        "iec_62443_fr1": 8,   # Identification and Authentication Control
        "iec_62443_fr2": 10,  # Use Control
        "iec_62443_fr3": 12,  # System Integrity
        "iec_62443_fr4": 10,  # Data Confidentiality
        "iec_62443_fr5": 8,   # Restricted Data Flow
        "iec_62443_fr6": 12,  # Timely Response to Events
        "iec_62443_fr7": 10,  # Resource Availability
        "nist_identify": 5,
        "nist_protect": 5,
        "nist_detect": 5,
        "nist_respond": 5,
        "nist_recover": 5,
        "backup_available": 5,
        "incident_response": 5,
        "change_management": 5,
        "security_monitoring": 5
    }

    @staticmethod
    def get_criticality_multiplier(device_type: str) -> float:
        """Get criticality multiplier for device type"""
        device_type_upper = device_type.upper()

        # Check for specific keywords
        if "SAFETY" in device_type_upper or "EMERGENCY" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["Safety PLC"]
        elif "SCADA" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["SCADA Server"]
        elif "HISTORIAN" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["Historian"]
        elif "PLC" in device_type_upper or "CONTROLLER" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["Production PLC"]
        elif "HMI" in device_type_upper or "WORKSTATION" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["HMI"]
        elif "SWITCH" in device_type_upper or "ROUTER" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["Switch"]
        elif "RTU" in device_type_upper:
            return ScoringRules.CRITICALITY_MULTIPLIERS["RTU"]
        else:
            return ScoringRules.CRITICALITY_MULTIPLIERS["Unknown"]

    @staticmethod
    def calculate_firmware_age_years(firmware_date: str) -> float:
        """Calculate firmware age in years"""
        try:
            if not firmware_date:
                return 0.0

            # Try parsing different date formats
            for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%Y", "%d/%m/%Y"]:
                try:
                    fw_date = datetime.strptime(firmware_date, fmt)
                    age_days = (datetime.now() - fw_date).days
                    return age_days / 365.25
                except ValueError:
                    continue

            # If it's just a year
            if len(firmware_date) == 4 and firmware_date.isdigit():
                year = int(firmware_date)
                current_year = datetime.now().year
                return current_year - year

            return 0.0
        except Exception:
            return 0.0

    @staticmethod
    def get_cvss_severity(cvss_score: float) -> str:
        """Get severity label from CVSS score"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score >= 0.1:
            return "LOW"
        else:
            return "INFO"

    @staticmethod
    def calculate_network_score(
        has_segmentation: bool,
        it_ot_separated: bool,
        internet_exposed_count: int,
        insecure_protocols: List[str],
        unnecessary_ports: List[int],
        has_firewall: bool,
        has_vlan: bool
    ) -> Tuple[float, List[str]]:
        """
        Calculate network security score
        Returns: (score, list of issues)
        """
        score = 100.0
        issues = []

        if not has_segmentation:
            score -= ScoringRules.NETWORK_DEDUCTIONS["no_segmentation"]
            issues.append("No network segmentation detected")

        if not it_ot_separated:
            score -= ScoringRules.NETWORK_DEDUCTIONS["no_it_ot_separation"]
            issues.append("IT and OT networks are not separated")

        if internet_exposed_count > 0:
            deduction = ScoringRules.NETWORK_DEDUCTIONS["internet_exposed"] * internet_exposed_count
            score -= deduction
            issues.append(f"{internet_exposed_count} device(s) exposed to internet")

        if insecure_protocols:
            deduction = ScoringRules.NETWORK_DEDUCTIONS["insecure_protocol"] * len(insecure_protocols)
            score -= deduction
            issues.append(f"Insecure protocols in use: {', '.join(insecure_protocols)}")

        if unnecessary_ports:
            deduction = ScoringRules.NETWORK_DEDUCTIONS["unnecessary_port"] * min(len(unnecessary_ports), 5)
            score -= deduction
            issues.append(f"{len(unnecessary_ports)} unnecessary port(s) open")

        if not has_firewall:
            score -= ScoringRules.NETWORK_DEDUCTIONS["no_firewall"]
            issues.append("No firewall detected")

        if not has_vlan:
            score -= ScoringRules.NETWORK_DEDUCTIONS["no_vlan"]
            issues.append("No VLAN segmentation")

        return max(0, score), issues

    @staticmethod
    def calculate_device_score(
        protection_level: int,
        has_default_credentials: bool,
        firmware_age_years: float,
        has_telnet: bool,
        has_ftp: bool,
        has_http_only: bool,
        debug_enabled: bool,
        unnecessary_services: List[str]
    ) -> Tuple[float, List[str]]:
        """
        Calculate device security score
        Returns: (score, list of issues)
        """
        score = 100.0
        issues = []

        # Protection level check
        if protection_level == 0:
            score -= ScoringRules.DEVICE_DEDUCTIONS["protection_level_0"]
            issues.append("Protection Level 0: No password protection")
        elif protection_level == 1:
            score -= ScoringRules.DEVICE_DEDUCTIONS["protection_level_1"]
            issues.append("Protection Level 1: Weak password protection")
        elif protection_level == 2:
            score -= ScoringRules.DEVICE_DEDUCTIONS["protection_level_2"]
            issues.append("Protection Level 2: Limited protection")

        # Default credentials
        if has_default_credentials:
            score -= ScoringRules.DEVICE_DEDUCTIONS["default_credentials"]
            issues.append("Default credentials detected")

        # Firmware age
        if firmware_age_years >= 5:
            score -= ScoringRules.DEVICE_DEDUCTIONS["firmware_age_5_plus_years"]
            issues.append(f"Firmware is {firmware_age_years:.1f} years old (critically outdated)")
        elif firmware_age_years >= 3:
            score -= ScoringRules.DEVICE_DEDUCTIONS["firmware_age_3_5_years"]
            issues.append(f"Firmware is {firmware_age_years:.1f} years old (outdated)")

        # Insecure services
        if has_telnet:
            score -= ScoringRules.DEVICE_DEDUCTIONS["telnet_enabled"]
            issues.append("Telnet service enabled (unencrypted)")

        if has_ftp:
            score -= ScoringRules.DEVICE_DEDUCTIONS["ftp_enabled"]
            issues.append("FTP service enabled (unencrypted)")

        if has_http_only:
            score -= ScoringRules.DEVICE_DEDUCTIONS["http_no_https"]
            issues.append("HTTP without HTTPS (no encryption)")

        if debug_enabled:
            score -= ScoringRules.DEVICE_DEDUCTIONS["debug_service_enabled"]
            issues.append("Debug services enabled")

        if unnecessary_services:
            deduction = ScoringRules.DEVICE_DEDUCTIONS["unnecessary_service"] * len(unnecessary_services)
            score -= deduction
            issues.append(f"{len(unnecessary_services)} unnecessary service(s) enabled")

        return max(0, score), issues

    @staticmethod
    def calculate_vulnerability_score(
        critical_cves_with_exploit: int,
        critical_cves_no_exploit: int,
        high_cves_with_exploit: int,
        high_cves_no_exploit: int,
        medium_cves: int,
        low_cves: int
    ) -> Tuple[float, List[str]]:
        """
        Calculate vulnerability score
        Returns: (score, list of issues)
        """
        score = 100.0
        issues = []

        # Critical CVEs with exploits
        if critical_cves_with_exploit > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["critical_cve_with_exploit"] * critical_cves_with_exploit
            score -= deduction
            issues.append(f"{critical_cves_with_exploit} CRITICAL CVE(s) with public exploit")

        # Critical CVEs without exploits
        if critical_cves_no_exploit > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["critical_cve_no_exploit"] * critical_cves_no_exploit
            score -= deduction
            issues.append(f"{critical_cves_no_exploit} CRITICAL CVE(s) without public exploit")

        # High CVEs with exploits
        if high_cves_with_exploit > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["high_cve_with_exploit"] * high_cves_with_exploit
            score -= deduction
            issues.append(f"{high_cves_with_exploit} HIGH CVE(s) with public exploit")

        # High CVEs without exploits
        if high_cves_no_exploit > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["high_cve_no_exploit"] * high_cves_no_exploit
            score -= deduction
            issues.append(f"{high_cves_no_exploit} HIGH CVE(s) without public exploit")

        # Medium CVEs
        if medium_cves > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["medium_cve"] * medium_cves
            score -= deduction
            issues.append(f"{medium_cves} MEDIUM severity CVE(s)")

        # Low CVEs
        if low_cves > 0:
            deduction = ScoringRules.VULNERABILITY_DEDUCTIONS["low_cve"] * low_cves
            score -= deduction
            issues.append(f"{low_cves} LOW severity CVE(s)")

        return max(0, score), issues

    @staticmethod
    def calculate_overall_score(
        network_score: float,
        device_score: float,
        vulnerability_score: float,
        compliance_score: float,
        criticality_multiplier: float = 1.0
    ) -> float:
        """
        Calculate overall risk score with weighting
        Returns risk score (0-100, higher = more risk)
        """
        weighted_sum = (
            network_score * ScoringRules.CATEGORY_WEIGHTS["network"] +
            device_score * ScoringRules.CATEGORY_WEIGHTS["device"] +
            vulnerability_score * ScoringRules.CATEGORY_WEIGHTS["vulnerability"] +
            compliance_score * ScoringRules.CATEGORY_WEIGHTS["compliance"]
        )

        # Convert to risk score (100 - security score)
        base_risk = 100 - weighted_sum

        # Apply criticality multiplier
        final_risk = min(100, base_risk * criticality_multiplier)

        return final_risk
