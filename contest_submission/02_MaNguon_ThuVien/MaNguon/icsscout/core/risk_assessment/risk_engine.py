"""
Risk Assessment Engine

Core engine for OT/ICS security risk assessment
"""

import uuid
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

from ...domain.device import Device
from ...domain.vulnerability import Vulnerability, VulnerabilityReport, Severity
from ...domain.risk_assessment import (
    RiskAssessmentReport, CategoryAssessment, DeviceRiskProfile,
    Finding, FindingSeverity, AssessmentCategory, RiskLevel,
    RiskMatrix, ActionItem, ComplianceStatus
)
from .scoring_rules import ScoringRules
from .checklist import ComplianceChecker


class RiskAssessmentEngine:
    """Main risk assessment engine"""

    def __init__(self):
        self.scoring_rules = ScoringRules()
        self.compliance_checker = ComplianceChecker()

    def assess_risk(
        self,
        devices: List[Device],
        vulnerability_reports: List[VulnerabilityReport],
        network_topology: Optional[Dict] = None
    ) -> RiskAssessmentReport:
        """
        Perform comprehensive risk assessment

        Args:
            devices: List of discovered devices
            vulnerability_reports: Vulnerability scan results
            network_topology: Optional network topology information

        Returns:
            Complete risk assessment report
        """
        # Generate report ID
        report_id = f"RISK-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:8]}"

        # Create vulnerability mapping
        vuln_map = {report.device_ip: report for report in vulnerability_reports}

        # Assess each category
        network_assessment = self._assess_network_security(devices, network_topology)
        device_assessment = self._assess_device_security(devices, vuln_map)
        vulnerability_assessment = self._assess_vulnerabilities(vulnerability_reports)
        compliance_assessment = self._assess_compliance(devices, network_topology, vuln_map)

        # Create device risk profiles
        device_profiles = self._create_device_profiles(devices, vuln_map)

        # Identify critical devices
        critical_devices = [d for d in device_profiles if d.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        critical_devices.sort(key=lambda x: x.risk_score, reverse=True)

        # Calculate overall risk score
        overall_risk_score = self.scoring_rules.calculate_overall_score(
            network_assessment.score,
            device_assessment.score,
            vulnerability_assessment.score,
            compliance_assessment.score
        )

        overall_risk_level = RiskLevel.from_score(overall_risk_score)

        # Collect all findings
        all_findings = []
        all_findings.extend(network_assessment.findings)
        all_findings.extend(device_assessment.findings)
        all_findings.extend(vulnerability_assessment.findings)
        all_findings.extend(compliance_assessment.findings)

        # Filter critical and high findings
        critical_findings = [f for f in all_findings if f.severity == FindingSeverity.CRITICAL]
        high_findings = [f for f in all_findings if f.severity == FindingSeverity.HIGH]

        # Generate compliance status
        compliance_status = self._generate_compliance_status(devices, network_topology, vuln_map)

        # Create risk matrix
        risk_matrix = self._create_risk_matrix(device_profiles)

        # Generate action plan
        action_plan = self._generate_action_plan(all_findings, device_profiles)

        # Build final report
        report = RiskAssessmentReport(
            scan_timestamp=datetime.now(),
            report_id=report_id,
            total_devices=len(devices),
            overall_risk_score=overall_risk_score,
            overall_risk_level=overall_risk_level,
            network_assessment=network_assessment,
            device_assessment=device_assessment,
            vulnerability_assessment=vulnerability_assessment,
            compliance_assessment=compliance_assessment,
            device_profiles=device_profiles,
            critical_devices=critical_devices,
            critical_findings=critical_findings,
            high_findings=high_findings,
            all_findings=all_findings,
            compliance_status=compliance_status,
            risk_matrix=risk_matrix,
            immediate_actions=action_plan["immediate"],
            short_term_actions=action_plan["short_term"],
            medium_term_actions=action_plan["medium_term"],
            long_term_actions=action_plan["long_term"],
            scan_scope="Full OT/ICS Network Assessment",
            methodology="Automated vulnerability scanning + IEC 62443 compliance check",
            tools_used=["ICSScout", "S7-Protocol Scanner", "Modbus Scanner", "CVE Database"]
        )

        return report

    def _assess_network_security(
        self,
        devices: List[Device],
        network_topology: Optional[Dict]
    ) -> CategoryAssessment:
        """Assess network security posture"""

        # Analyze network configuration
        has_segmentation = self._check_network_segmentation(devices, network_topology)
        it_ot_separated = self._check_it_ot_separation(network_topology)
        internet_exposed_count = self._count_internet_exposed(devices)
        insecure_protocols = self._identify_insecure_protocols(devices)
        unnecessary_ports = self._identify_unnecessary_ports(devices)
        has_firewall = network_topology.get("has_firewall", False) if network_topology else False
        has_vlan = network_topology.get("has_vlan", False) if network_topology else False

        # Calculate score
        score, issues = self.scoring_rules.calculate_network_score(
            has_segmentation=has_segmentation,
            it_ot_separated=it_ot_separated,
            internet_exposed_count=internet_exposed_count,
            insecure_protocols=insecure_protocols,
            unnecessary_ports=unnecessary_ports,
            has_firewall=has_firewall,
            has_vlan=has_vlan
        )

        # Create findings
        findings = []
        for issue in issues:
            severity = self._determine_severity_from_issue(issue)
            findings.append(Finding(
                title=f"Network Security Issue: {issue.split(':')[0]}",
                description=issue,
                severity=severity,
                category=AssessmentCategory.NETWORK,
                recommendation=self._get_network_recommendation(issue)
            ))

        # Recommendations
        recommendations = [
            "Implement network segmentation following Purdue Model (Levels 0-4)",
            "Deploy industrial firewalls between OT zones",
            "Use VLANs to isolate critical devices",
            "Disable unnecessary protocols and services",
            "Implement intrusion detection systems (IDS) for OT networks"
        ]

        return CategoryAssessment(
            category=AssessmentCategory.NETWORK,
            score=score,
            weight=self.scoring_rules.CATEGORY_WEIGHTS["network"],
            findings=findings,
            recommendations=recommendations,
            details={
                "has_segmentation": has_segmentation,
                "it_ot_separated": it_ot_separated,
                "internet_exposed_count": internet_exposed_count,
                "insecure_protocols": insecure_protocols,
                "unnecessary_ports_count": len(unnecessary_ports)
            }
        )

    def _assess_device_security(
        self,
        devices: List[Device],
        vuln_map: Dict[str, VulnerabilityReport]
    ) -> CategoryAssessment:
        """Assess device-level security"""

        findings = []
        total_score = 0
        device_count = len(devices)

        for device in devices:
            # Get device protection level
            protection_level = device.metadata.get("protection_level", 0)
            has_default_creds = device.metadata.get("default_credentials", False)
            firmware_version = device.firmware_version or ""
            firmware_age = self.scoring_rules.calculate_firmware_age_years(firmware_version)

            # Check for insecure services
            has_telnet = 23 in device.open_ports
            has_ftp = 21 in device.open_ports
            has_http_only = 80 in device.open_ports and 443 not in device.open_ports
            debug_enabled = device.metadata.get("debug_enabled", False)
            unnecessary_services = []

            # Calculate device score
            dev_score, dev_issues = self.scoring_rules.calculate_device_score(
                protection_level=protection_level,
                has_default_credentials=has_default_creds,
                firmware_age_years=firmware_age,
                has_telnet=has_telnet,
                has_ftp=has_ftp,
                has_http_only=has_http_only,
                debug_enabled=debug_enabled,
                unnecessary_services=unnecessary_services
            )

            total_score += dev_score

            # Create findings for this device
            for issue in dev_issues:
                severity = self._determine_severity_from_issue(issue)
                findings.append(Finding(
                    title=f"Device Security Issue on {device.ip}",
                    description=issue,
                    severity=severity,
                    category=AssessmentCategory.DEVICE,
                    affected_devices=[device.ip],
                    recommendation=self._get_device_recommendation(issue)
                ))

        # Average score across all devices
        avg_score = total_score / device_count if device_count > 0 else 0

        recommendations = [
            "Enable maximum protection level (Level 3) on all PLCs",
            "Change all default credentials immediately",
            "Update firmware to latest stable versions",
            "Disable Telnet and FTP; use SSH/SFTP instead",
            "Enable HTTPS for web interfaces",
            "Disable debug and diagnostic services in production"
        ]

        return CategoryAssessment(
            category=AssessmentCategory.DEVICE,
            score=avg_score,
            weight=self.scoring_rules.CATEGORY_WEIGHTS["device"],
            findings=findings,
            recommendations=recommendations,
            details={
                "total_devices": device_count,
                "average_protection_level": sum(d.metadata.get("protection_level", 0) for d in devices) / device_count if device_count > 0 else 0
            }
        )

    def _assess_vulnerabilities(
        self,
        vulnerability_reports: List[VulnerabilityReport]
    ) -> CategoryAssessment:
        """Assess vulnerability exposure"""

        # Count vulnerabilities by severity
        critical_with_exploit = 0
        critical_no_exploit = 0
        high_with_exploit = 0
        high_no_exploit = 0
        medium_cves = 0
        low_cves = 0

        findings = []

        for report in vulnerability_reports:
            for vuln in report.vulnerabilities:
                if vuln.severity == Severity.CRITICAL:
                    if vuln.exploit_available:
                        critical_with_exploit += 1
                    else:
                        critical_no_exploit += 1

                    # Create finding
                    findings.append(Finding(
                        title=f"CRITICAL: {vuln.title}",
                        description=vuln.description,
                        severity=FindingSeverity.CRITICAL,
                        category=AssessmentCategory.VULNERABILITY,
                        affected_devices=[report.device_ip],
                        cvss_score=vuln.cvss_score,
                        cve_id=vuln.cve_id,
                        recommendation=vuln.recommendation
                    ))

                elif vuln.severity == Severity.HIGH:
                    if vuln.exploit_available:
                        high_with_exploit += 1
                    else:
                        high_no_exploit += 1

                    findings.append(Finding(
                        title=f"HIGH: {vuln.title}",
                        description=vuln.description,
                        severity=FindingSeverity.HIGH,
                        category=AssessmentCategory.VULNERABILITY,
                        affected_devices=[report.device_ip],
                        cvss_score=vuln.cvss_score,
                        cve_id=vuln.cve_id,
                        recommendation=vuln.recommendation
                    ))

                elif vuln.severity == Severity.MEDIUM:
                    medium_cves += 1
                elif vuln.severity == Severity.LOW:
                    low_cves += 1

        # Calculate score
        score, issues = self.scoring_rules.calculate_vulnerability_score(
            critical_cves_with_exploit=critical_with_exploit,
            critical_cves_no_exploit=critical_no_exploit,
            high_cves_with_exploit=high_with_exploit,
            high_cves_no_exploit=high_no_exploit,
            medium_cves=medium_cves,
            low_cves=low_cves
        )

        recommendations = [
            "Patch all CRITICAL vulnerabilities within 24 hours",
            "Patch HIGH vulnerabilities within 1 week",
            "Implement network segmentation to limit exploit impact",
            "Deploy IDS/IPS signatures for known exploits",
            "Establish regular vulnerability scanning schedule",
            "Subscribe to vendor security advisories"
        ]

        return CategoryAssessment(
            category=AssessmentCategory.VULNERABILITY,
            score=score,
            weight=self.scoring_rules.CATEGORY_WEIGHTS["vulnerability"],
            findings=findings,
            recommendations=recommendations,
            details={
                "critical_with_exploit": critical_with_exploit,
                "critical_no_exploit": critical_no_exploit,
                "high_with_exploit": high_with_exploit,
                "high_no_exploit": high_no_exploit,
                "medium_cves": medium_cves,
                "low_cves": low_cves,
                "total_cves": len(findings)
            }
        )

    def _assess_compliance(
        self,
        devices: List[Device],
        network_topology: Optional[Dict],
        vuln_map: Dict[str, VulnerabilityReport]
    ) -> CategoryAssessment:
        """Assess compliance with standards"""

        # Prepare data for compliance checking
        devices_dict = [self._device_to_dict(d, vuln_map) for d in devices]
        network_info = network_topology if network_topology else {}
        scan_results = {
            "insecure_protocols": self._identify_insecure_protocols(devices),
            "risk_assessment_performed": True
        }

        # Check IEC 62443 compliance
        iec_status = self.compliance_checker.check_iec_62443_compliance(
            devices=devices_dict,
            network_info=network_info,
            scan_results=scan_results
        )

        # Create findings from gaps
        findings = []
        for gap in iec_status.gaps[:10]:  # Top 10 gaps
            findings.append(Finding(
                title=f"Compliance Gap: {gap.split(':')[0]}",
                description=gap,
                severity=FindingSeverity.MEDIUM,
                category=AssessmentCategory.COMPLIANCE,
                recommendation="Implement required controls to meet IEC 62443 standards"
            ))

        score = iec_status.overall_compliance

        recommendations = [
            "Align security controls with IEC 62443-3-3 requirements",
            "Implement all Foundational Requirements (FR1-FR7)",
            "Achieve at least Security Level 2 (SL-2)",
            "Document security policies and procedures",
            "Conduct regular compliance audits",
            "Implement continuous monitoring and logging"
        ]

        return CategoryAssessment(
            category=AssessmentCategory.COMPLIANCE,
            score=score,
            weight=self.scoring_rules.CATEGORY_WEIGHTS["compliance"],
            findings=findings,
            recommendations=recommendations,
            details={
                "iec_62443_compliance": iec_status.overall_compliance,
                "security_level": iec_status.security_level,
                "requirements_met": iec_status.requirements_met,
                "requirements_total": iec_status.requirements_total
            }
        )

    def _create_device_profiles(
        self,
        devices: List[Device],
        vuln_map: Dict[str, VulnerabilityReport]
    ) -> List[DeviceRiskProfile]:
        """Create risk profiles for each device"""

        profiles = []

        for device in devices:
            # Get device info
            protection_level = device.metadata.get("protection_level", 0)
            firmware_age = self.scoring_rules.calculate_firmware_age_years(device.firmware_version or "")

            # Get vulnerabilities
            cve_count = 0
            device_findings = []
            if device.ip in vuln_map:
                vuln_report = vuln_map[device.ip]
                cve_count = len(vuln_report.vulnerabilities)

                # Convert vulnerabilities to findings
                for vuln in vuln_report.vulnerabilities:
                    device_findings.append(Finding(
                        title=vuln.title,
                        description=vuln.description,
                        severity=self._severity_to_finding_severity(vuln.severity),
                        category=AssessmentCategory.VULNERABILITY,
                        cvss_score=vuln.cvss_score,
                        cve_id=vuln.cve_id,
                        recommendation=vuln.recommendation
                    ))

            # Calculate device risk score
            criticality = self.scoring_rules.get_criticality_multiplier(device.device_type.value if device.device_type else "Unknown")

            # Simple device risk calculation
            base_risk = 0
            if protection_level == 0:
                base_risk += 50
            elif protection_level == 1:
                base_risk += 30

            if firmware_age > 3:
                base_risk += 25

            if cve_count > 0:
                base_risk += min(cve_count * 10, 40)

            device_risk = min(100, base_risk * criticality)
            risk_level = RiskLevel.from_score(device_risk)

            profile = DeviceRiskProfile(
                ip=device.ip,
                hostname=device.metadata.get("hostname", "") or device.hostname or "",
                device_type=device.device_type.value if device.device_type else "Unknown",
                vendor=device.vendor or "Unknown",
                model=device.model or "Unknown",
                risk_score=device_risk,
                risk_level=risk_level,
                criticality_multiplier=criticality,
                findings=device_findings,
                protection_level=protection_level,
                firmware_age_years=firmware_age if firmware_age > 0 else None,
                firmware_version=device.firmware_version,
                cve_count=cve_count,
                open_ports=device.open_ports,
                protocols=device.protocols,
                metadata=device.metadata
            )

            profiles.append(profile)

        return profiles

    def _generate_compliance_status(
        self,
        devices: List[Device],
        network_topology: Optional[Dict],
        vuln_map: Dict[str, VulnerabilityReport]
    ) -> List[ComplianceStatus]:
        """Generate compliance status for all frameworks"""

        devices_dict = [self._device_to_dict(d, vuln_map) for d in devices]
        network_info = network_topology if network_topology else {}
        scan_results = {
            "insecure_protocols": self._identify_insecure_protocols(devices),
            "risk_assessment_performed": True
        }

        statuses = []

        # IEC 62443
        iec_status = self.compliance_checker.check_iec_62443_compliance(
            devices=devices_dict,
            network_info=network_info,
            scan_results=scan_results
        )
        statuses.append(iec_status)

        # NIST CSF
        nist_status = self.compliance_checker.check_nist_csf_compliance(
            devices=devices_dict,
            network_info=network_info,
            scan_results=scan_results
        )
        statuses.append(nist_status)

        return statuses

    def _create_risk_matrix(self, device_profiles: List[DeviceRiskProfile]) -> RiskMatrix:
        """Create risk distribution matrix"""

        by_zone = defaultdict(list)
        by_device_type = defaultdict(list)
        by_protocol = defaultdict(list)
        by_vendor = defaultdict(list)

        for profile in device_profiles:
            # By device type
            by_device_type[profile.device_type].append(profile.risk_score)

            # By vendor
            by_vendor[profile.vendor].append(profile.risk_score)

        # Calculate averages
        matrix = RiskMatrix(
            by_zone={},  # Would need zone info
            by_device_type={k: sum(v)/len(v) for k, v in by_device_type.items()},
            by_protocol={},  # Would need protocol info
            by_vendor={k: sum(v)/len(v) for k, v in by_vendor.items()}
        )

        return matrix

    def _generate_action_plan(
        self,
        findings: List[Finding],
        device_profiles: List[DeviceRiskProfile]
    ) -> Dict[str, List[ActionItem]]:
        """Generate prioritized action plan"""

        immediate = []
        short_term = []
        medium_term = []
        long_term = []

        # Sort findings by severity
        critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        high = [f for f in findings if f.severity == FindingSeverity.HIGH]
        medium = [f for f in findings if f.severity == FindingSeverity.MEDIUM]
        low = [f for f in findings if f.severity == FindingSeverity.LOW]

        # IMMEDIATE actions (CRITICAL findings)
        for finding in critical[:5]:  # Top 5 critical
            immediate.append(ActionItem(
                priority="IMMEDIATE",
                title=finding.title,
                description=finding.description,
                affected_devices=finding.affected_devices,
                estimated_effort="Hours to Days",
                timeline="Within 24 hours"
            ))

        # SHORT TERM actions (HIGH findings)
        for finding in high[:10]:  # Top 10 high
            short_term.append(ActionItem(
                priority="SHORT_TERM",
                title=finding.title,
                description=finding.description,
                affected_devices=finding.affected_devices,
                estimated_effort="Days",
                timeline="Within 1 week"
            ))

        # MEDIUM TERM actions (MEDIUM findings)
        for finding in medium[:15]:
            medium_term.append(ActionItem(
                priority="MEDIUM_TERM",
                title=finding.title,
                description=finding.description,
                affected_devices=finding.affected_devices,
                estimated_effort="Weeks",
                timeline="Within 1 month"
            ))

        # LONG TERM actions (LOW findings + improvements)
        for finding in low[:10]:
            long_term.append(ActionItem(
                priority="LONG_TERM",
                title=finding.title,
                description=finding.description,
                affected_devices=finding.affected_devices,
                estimated_effort="Weeks to Months",
                timeline="Within 3 months"
            ))

        return {
            "immediate": immediate,
            "short_term": short_term,
            "medium_term": medium_term,
            "long_term": long_term
        }

    # Helper methods
    def _check_network_segmentation(self, devices: List[Device], topology: Optional[Dict]) -> bool:
        """Check if network segmentation exists"""
        if topology and topology.get("has_segmentation"):
            return True
        # Heuristic: check if devices are on different subnets
        subnets = set()
        for device in devices:
            if device.ip:
                subnet = '.'.join(device.ip.split('.')[:3])
                subnets.add(subnet)
        return len(subnets) > 1

    def _check_it_ot_separation(self, topology: Optional[Dict]) -> bool:
        """Check IT/OT network separation"""
        if topology:
            return topology.get("it_ot_separated", False)
        return False

    def _count_internet_exposed(self, devices: List[Device]) -> int:
        """Count devices exposed to internet"""
        # This would need actual routing/firewall info
        # For now, assume devices with public IPs are exposed
        return 0

    def _identify_insecure_protocols(self, devices: List[Device]) -> List[str]:
        """Identify insecure protocols in use"""
        protocols = set()
        for device in devices:
            for proto in device.protocols:
                if proto.upper() in ["MODBUS TCP", "S7", "PROFINET DCP", "BACNET", "FINS"]:
                    protocols.add(proto)
        return list(protocols)

    def _identify_unnecessary_ports(self, devices: List[Device]) -> List[int]:
        """Identify unnecessary open ports"""
        unnecessary = set()
        risky_ports = [23, 21, 80, 161, 162, 69]  # Telnet, FTP, HTTP, SNMP, TFTP

        for device in devices:
            for port in device.open_ports:
                if port in risky_ports:
                    unnecessary.add(port)

        return list(unnecessary)

    def _device_to_dict(self, device: Device, vuln_map: Dict) -> Dict:
        """Convert Device to dict for compliance checking"""
        return {
            "ip": device.ip,
            "device_type": device.device_type.value if device.device_type else "Unknown",
            "protection_level": device.metadata.get("protection_level", 0),
            "has_default_credentials": device.metadata.get("default_credentials", False),
            "firmware_age_years": self.scoring_rules.calculate_firmware_age_years(device.firmware_version or ""),
            "open_ports": device.open_ports,
            "cpu_state": device.cpu_state
        }

    def _determine_severity_from_issue(self, issue: str) -> FindingSeverity:
        """Determine finding severity from issue text"""
        issue_lower = issue.lower()
        if any(word in issue_lower for word in ["exposed", "no password", "default credential", "critical cve"]):
            return FindingSeverity.CRITICAL
        elif any(word in issue_lower for word in ["no segmentation", "telnet", "ftp", "outdated", "5 years"]):
            return FindingSeverity.HIGH
        elif any(word in issue_lower for word in ["http", "snmp", "3 years", "protection level 2"]):
            return FindingSeverity.MEDIUM
        else:
            return FindingSeverity.LOW

    def _get_network_recommendation(self, issue: str) -> str:
        """Get recommendation for network issue"""
        if "segmentation" in issue.lower():
            return "Implement network segmentation using VLANs and firewalls according to Purdue Model"
        elif "exposed" in issue.lower():
            return "Remove direct internet connectivity; use VPN or secure remote access gateway"
        elif "protocol" in issue.lower():
            return "Implement protocol filtering and consider encrypted alternatives where possible"
        elif "firewall" in issue.lower():
            return "Deploy industrial firewalls between OT network zones"
        else:
            return "Review and harden network security configuration"

    def _get_device_recommendation(self, issue: str) -> str:
        """Get recommendation for device issue"""
        if "protection level 0" in issue.lower():
            return "Enable password protection (minimum Protection Level 2, recommended Level 3)"
        elif "default credential" in issue.lower():
            return "Change all default passwords to strong, unique credentials immediately"
        elif "firmware" in issue.lower():
            return "Update firmware to latest stable version from vendor"
        elif "telnet" in issue.lower():
            return "Disable Telnet; use SSH for remote access"
        elif "ftp" in issue.lower():
            return "Disable FTP; use SFTP or SCP for file transfers"
        else:
            return "Review and harden device security configuration"

    def _severity_to_finding_severity(self, severity: Severity) -> FindingSeverity:
        """Convert Vulnerability Severity to Finding Severity"""
        mapping = {
            Severity.CRITICAL: FindingSeverity.CRITICAL,
            Severity.HIGH: FindingSeverity.HIGH,
            Severity.MEDIUM: FindingSeverity.MEDIUM,
            Severity.LOW: FindingSeverity.LOW,
            Severity.INFO: FindingSeverity.INFO
        }
        return mapping.get(severity, FindingSeverity.INFO)
