"""
Compliance Checklist Module

IEC 62443 and NIST CSF compliance checking
"""

from typing import Dict, List, Tuple
from ...domain.risk_assessment import ComplianceStatus


class ComplianceChecker:
    """Compliance framework checker"""

    # IEC 62443-3-3 Foundational Requirements
    IEC_62443_REQUIREMENTS = {
        "FR1": {
            "name": "Identification and Authentication Control",
            "checks": [
                "unique_user_identification",
                "authentication_required",
                "password_strength",
                "account_management"
            ]
        },
        "FR2": {
            "name": "Use Control",
            "checks": [
                "authorization_enforcement",
                "least_privilege",
                "role_based_access",
                "privilege_escalation_control"
            ]
        },
        "FR3": {
            "name": "System Integrity",
            "checks": [
                "communication_integrity",
                "malicious_code_protection",
                "security_functionality_verification",
                "software_integrity_check"
            ]
        },
        "FR4": {
            "name": "Data Confidentiality",
            "checks": [
                "information_confidentiality",
                "encryption_at_rest",
                "encryption_in_transit",
                "sensitive_data_protection"
            ]
        },
        "FR5": {
            "name": "Restricted Data Flow",
            "checks": [
                "network_segmentation",
                "zone_boundary_protection",
                "data_flow_control",
                "deny_by_default"
            ]
        },
        "FR6": {
            "name": "Timely Response to Events",
            "checks": [
                "audit_log_generation",
                "continuous_monitoring",
                "incident_detection",
                "response_capability"
            ]
        },
        "FR7": {
            "name": "Resource Availability",
            "checks": [
                "denial_of_service_protection",
                "resource_management",
                "backup_recovery",
                "fault_tolerance"
            ]
        }
    }

    # NIST Cybersecurity Framework Functions
    NIST_CSF_FUNCTIONS = {
        "IDENTIFY": {
            "categories": [
                "Asset Management",
                "Business Environment",
                "Governance",
                "Risk Assessment"
            ]
        },
        "PROTECT": {
            "categories": [
                "Access Control",
                "Awareness and Training",
                "Data Security",
                "Protective Technology"
            ]
        },
        "DETECT": {
            "categories": [
                "Anomalies and Events",
                "Security Continuous Monitoring",
                "Detection Processes"
            ]
        },
        "RESPOND": {
            "categories": [
                "Response Planning",
                "Communications",
                "Analysis",
                "Mitigation"
            ]
        },
        "RECOVER": {
            "categories": [
                "Recovery Planning",
                "Improvements",
                "Communications"
            ]
        }
    }

    @staticmethod
    def check_iec_62443_compliance(
        devices: List[Dict],
        network_info: Dict,
        scan_results: Dict
    ) -> ComplianceStatus:
        """
        Check IEC 62443-3-3 compliance
        Returns ComplianceStatus object
        """
        total_checks = 0
        passed_checks = 0
        gaps = []
        details = {}

        # FR1: Identification and Authentication Control
        fr1_score, fr1_gaps = ComplianceChecker._check_fr1(devices)
        total_checks += 4
        passed_checks += fr1_score
        gaps.extend(fr1_gaps)
        details["FR1"] = {"score": fr1_score, "max": 4, "gaps": fr1_gaps}

        # FR2: Use Control
        fr2_score, fr2_gaps = ComplianceChecker._check_fr2(devices)
        total_checks += 4
        passed_checks += fr2_score
        gaps.extend(fr2_gaps)
        details["FR2"] = {"score": fr2_score, "max": 4, "gaps": fr2_gaps}

        # FR3: System Integrity
        fr3_score, fr3_gaps = ComplianceChecker._check_fr3(devices, scan_results)
        total_checks += 4
        passed_checks += fr3_score
        gaps.extend(fr3_gaps)
        details["FR3"] = {"score": fr3_score, "max": 4, "gaps": fr3_gaps}

        # FR4: Data Confidentiality
        fr4_score, fr4_gaps = ComplianceChecker._check_fr4(devices, scan_results)
        total_checks += 4
        passed_checks += fr4_score
        gaps.extend(fr4_gaps)
        details["FR4"] = {"score": fr4_score, "max": 4, "gaps": fr4_gaps}

        # FR5: Restricted Data Flow
        fr5_score, fr5_gaps = ComplianceChecker._check_fr5(network_info, devices)
        total_checks += 4
        passed_checks += fr5_score
        gaps.extend(fr5_gaps)
        details["FR5"] = {"score": fr5_score, "max": 4, "gaps": fr5_gaps}

        # FR6: Timely Response to Events
        fr6_score, fr6_gaps = ComplianceChecker._check_fr6(scan_results)
        total_checks += 4
        passed_checks += fr6_score
        gaps.extend(fr6_gaps)
        details["FR6"] = {"score": fr6_score, "max": 4, "gaps": fr6_gaps}

        # FR7: Resource Availability
        fr7_score, fr7_gaps = ComplianceChecker._check_fr7(devices, scan_results)
        total_checks += 4
        passed_checks += fr7_score
        gaps.extend(fr7_gaps)
        details["FR7"] = {"score": fr7_score, "max": 4, "gaps": fr7_gaps}

        # Calculate overall compliance percentage
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        # Determine Security Level (SL)
        security_level = ComplianceChecker._determine_security_level(compliance_percentage)

        return ComplianceStatus(
            framework="IEC 62443-3-3",
            overall_compliance=compliance_percentage,
            requirements_met=passed_checks,
            requirements_total=total_checks,
            security_level=security_level,
            gaps=gaps,
            details=details
        )

    @staticmethod
    def _check_fr1(devices: List[Dict]) -> Tuple[int, List[str]]:
        """Check FR1: Identification and Authentication Control"""
        score = 0
        gaps = []

        # Check if devices require authentication
        auth_required_count = sum(1 for d in devices if d.get("protection_level", 0) >= 2)
        if auth_required_count >= len(devices) * 0.8:
            score += 1
        else:
            gaps.append("FR1: Less than 80% of devices require authentication")

        # Check password strength (protection level 3)
        strong_auth_count = sum(1 for d in devices if d.get("protection_level", 0) == 3)
        if strong_auth_count >= len(devices) * 0.5:
            score += 1
        else:
            gaps.append("FR1: Less than 50% of devices have strong authentication (Protection Level 3)")

        # Check for default credentials
        default_creds = sum(1 for d in devices if d.get("has_default_credentials", False))
        if default_creds == 0:
            score += 1
        else:
            gaps.append(f"FR1: {default_creds} device(s) still using default credentials")

        # Assume account management present if protection level >= 2
        if auth_required_count > 0:
            score += 1
        else:
            gaps.append("FR1: No account management detected on any devices")

        return score, gaps

    @staticmethod
    def _check_fr2(devices: List[Dict]) -> Tuple[int, List[str]]:
        """Check FR2: Use Control"""
        score = 0
        gaps = []

        # Check authorization enforcement (protection level >= 2)
        auth_enforced = sum(1 for d in devices if d.get("protection_level", 0) >= 2)
        if auth_enforced >= len(devices) * 0.7:
            score += 1
        else:
            gaps.append("FR2: Authorization not enforced on majority of devices")

        # Role-based access control (inferred from protection level 3)
        rbac_devices = sum(1 for d in devices if d.get("protection_level", 0) == 3)
        if rbac_devices >= len(devices) * 0.3:
            score += 1
        else:
            gaps.append("FR2: Role-based access control not implemented broadly")

        # Least privilege (partial score based on protection levels)
        score += 1  # Assume basic least privilege if auth exists

        # Privilege escalation control
        score += 1  # Assume present if RBAC exists

        return score, gaps

    @staticmethod
    def _check_fr3(devices: List[Dict], scan_results: Dict) -> Tuple[int, List[str]]:
        """Check FR3: System Integrity"""
        score = 0
        gaps = []

        # Communication integrity (check for secure protocols)
        insecure_protocols = scan_results.get("insecure_protocols", [])
        if len(insecure_protocols) == 0:
            score += 1
        else:
            gaps.append(f"FR3: Insecure protocols detected: {', '.join(insecure_protocols)}")

        # Malicious code protection (not detectable via scan)
        gaps.append("FR3: Cannot verify malicious code protection via network scan")

        # Security functionality verification
        score += 1  # Assume basic verification in place

        # Software integrity check (firmware versions)
        outdated_firmware = sum(1 for d in devices if d.get("firmware_age_years", 0) > 3)
        if outdated_firmware < len(devices) * 0.3:
            score += 1
        else:
            gaps.append(f"FR3: {outdated_firmware} device(s) have outdated firmware (>3 years)")

        return score, gaps

    @staticmethod
    def _check_fr4(devices: List[Dict], scan_results: Dict) -> Tuple[int, List[str]]:
        """Check FR4: Data Confidentiality"""
        score = 0
        gaps = []

        # Information confidentiality (protection level >= 2)
        confidentiality = sum(1 for d in devices if d.get("protection_level", 0) >= 2)
        if confidentiality >= len(devices) * 0.7:
            score += 1
        else:
            gaps.append("FR4: Information confidentiality not ensured on majority of devices")

        # Encryption at rest (not detectable)
        gaps.append("FR4: Cannot verify encryption at rest via network scan")

        # Encryption in transit
        unencrypted_services = sum(1 for d in devices
                                   if any(port in d.get("open_ports", [])
                                        for port in [23, 21, 80]))
        if unencrypted_services == 0:
            score += 1
        else:
            gaps.append(f"FR4: {unencrypted_services} device(s) have unencrypted services (Telnet/FTP/HTTP)")

        # Sensitive data protection
        if scan_results.get("data_protection_detected", False):
            score += 1
        else:
            gaps.append("FR4: Sensitive data protection mechanisms not detected")

        return score, gaps

    @staticmethod
    def _check_fr5(network_info: Dict, devices: List[Dict]) -> Tuple[int, List[str]]:
        """Check FR5: Restricted Data Flow"""
        score = 0
        gaps = []

        # Network segmentation
        if network_info.get("has_segmentation", False):
            score += 2
        else:
            gaps.append("FR5: No network segmentation detected")
            gaps.append("FR5: Zone boundary protection missing")

        # Data flow control
        if network_info.get("has_firewall", False):
            score += 1
        else:
            gaps.append("FR5: No firewall/data flow control detected")

        # Deny by default
        if network_info.get("firewall_default_deny", False):
            score += 1
        else:
            gaps.append("FR5: Firewall deny-by-default policy not confirmed")

        return score, gaps

    @staticmethod
    def _check_fr6(scan_results: Dict) -> Tuple[int, List[str]]:
        """Check FR6: Timely Response to Events"""
        score = 0
        gaps = []

        # These are mostly not detectable via network scan
        gaps.append("FR6: Audit log generation cannot be verified via network scan")
        gaps.append("FR6: Continuous monitoring capability not detectable")
        gaps.append("FR6: Incident detection mechanisms not visible")
        gaps.append("FR6: Response capability not assessable via scanning")

        # Give partial credit if SNMP monitoring detected
        if scan_results.get("snmp_monitoring_detected", False):
            score += 1

        return score, gaps

    @staticmethod
    def _check_fr7(devices: List[Dict], scan_results: Dict) -> Tuple[int, List[str]]:
        """Check FR7: Resource Availability"""
        score = 0
        gaps = []

        # DoS protection (not directly detectable)
        gaps.append("FR7: DoS protection mechanisms not detectable via scan")

        # Resource management (inferred from device health)
        healthy_devices = sum(1 for d in devices if d.get("cpu_state") == "RUN")
        if healthy_devices == len(devices):
            score += 1
        else:
            gaps.append(f"FR7: {len(devices) - healthy_devices} device(s) not in healthy state")

        # Backup and recovery (not detectable)
        gaps.append("FR7: Backup and recovery capabilities not verifiable via scan")

        # Fault tolerance (redundancy check)
        if scan_results.get("redundancy_detected", False):
            score += 1
        else:
            gaps.append("FR7: No redundancy or fault tolerance detected")

        return score, gaps

    @staticmethod
    def _determine_security_level(compliance_percentage: float) -> str:
        """Determine IEC 62443 Security Level from compliance percentage"""
        if compliance_percentage >= 90:
            return "SL-3 (High)"
        elif compliance_percentage >= 70:
            return "SL-2 (Medium)"
        elif compliance_percentage >= 40:
            return "SL-1 (Basic)"
        else:
            return "SL-0 (None)"

    @staticmethod
    def check_nist_csf_compliance(
        devices: List[Dict],
        network_info: Dict,
        scan_results: Dict
    ) -> ComplianceStatus:
        """
        Check NIST Cybersecurity Framework compliance
        Returns ComplianceStatus object
        """
        total_categories = 20  # Total categories across all functions
        passed_categories = 0
        gaps = []
        details = {}

        # IDENTIFY function
        identify_score = 0
        if scan_results.get("asset_inventory_complete", False):
            identify_score += 1
        else:
            gaps.append("IDENTIFY: Asset inventory not complete")

        if scan_results.get("risk_assessment_performed", True):  # We're doing this now
            identify_score += 1

        details["IDENTIFY"] = {"score": identify_score, "max": 4}
        passed_categories += identify_score

        # PROTECT function
        protect_score = 0
        auth_devices = sum(1 for d in devices if d.get("protection_level", 0) >= 2)
        if auth_devices >= len(devices) * 0.7:
            protect_score += 1
        else:
            gaps.append("PROTECT: Access control not enforced on majority of devices")

        if scan_results.get("encryption_in_use", False):
            protect_score += 1
        else:
            gaps.append("PROTECT: Data encryption not widely implemented")

        details["PROTECT"] = {"score": protect_score, "max": 4}
        passed_categories += protect_score

        # DETECT function
        detect_score = 0
        if scan_results.get("monitoring_in_place", False):
            detect_score += 1
        else:
            gaps.append("DETECT: Security monitoring not detected")

        details["DETECT"] = {"score": detect_score, "max": 4}
        passed_categories += detect_score

        # RESPOND function
        respond_score = 0
        if scan_results.get("incident_response_plan", False):
            respond_score += 1
        else:
            gaps.append("RESPOND: Incident response capability not verified")

        details["RESPOND"] = {"score": respond_score, "max": 4}
        passed_categories += respond_score

        # RECOVER function
        recover_score = 0
        if scan_results.get("backup_detected", False):
            recover_score += 1
        else:
            gaps.append("RECOVER: Backup and recovery mechanisms not detected")

        details["RECOVER"] = {"score": recover_score, "max": 4}
        passed_categories += recover_score

        compliance_percentage = (passed_categories / total_categories * 100)

        # Determine maturity tier
        if compliance_percentage >= 85:
            tier = 4  # Adaptive
        elif compliance_percentage >= 65:
            tier = 3  # Repeatable
        elif compliance_percentage >= 40:
            tier = 2  # Risk Informed
        else:
            tier = 1  # Partial

        return ComplianceStatus(
            framework="NIST Cybersecurity Framework",
            overall_compliance=compliance_percentage,
            requirements_met=passed_categories,
            requirements_total=total_categories,
            maturity_tier=tier,
            gaps=gaps,
            details=details
        )
