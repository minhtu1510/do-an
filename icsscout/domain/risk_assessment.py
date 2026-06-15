"""
Risk Assessment Domain Models

Models for OT/ICS security risk assessment framework
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_range(self) -> tuple:
        """Get score range for this risk level"""
        ranges = {
            RiskLevel.CRITICAL: (90, 100),
            RiskLevel.HIGH: (70, 89),
            RiskLevel.MEDIUM: (40, 69),
            RiskLevel.LOW: (20, 39),
            RiskLevel.INFO: (0, 19)
        }
        return ranges[self]

    @property
    def color(self) -> str:
        """Get color code for UI"""
        colors = {
            RiskLevel.CRITICAL: "#dc3545",  # Red
            RiskLevel.HIGH: "#fd7e14",      # Orange
            RiskLevel.MEDIUM: "#ffc107",    # Yellow
            RiskLevel.LOW: "#28a745",       # Green
            RiskLevel.INFO: "#6c757d"       # Gray
        }
        return colors[self]

    @property
    def icon(self) -> str:
        """Get emoji icon"""
        icons = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH: "🟠",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.LOW: "🟢",
            RiskLevel.INFO: "⚪"
        }
        return icons[self]

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Determine risk level from score"""
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO


class FindingSeverity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AssessmentCategory(Enum):
    """Assessment category types"""
    NETWORK = "Network Security"
    DEVICE = "Device Security"
    VULNERABILITY = "Vulnerability Assessment"
    COMPLIANCE = "Compliance & Best Practices"


@dataclass
class Finding:
    """Security finding/issue"""
    title: str
    description: str
    severity: FindingSeverity
    category: AssessmentCategory
    affected_devices: List[str] = field(default_factory=list)
    recommendation: str = ""
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    impact: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "affected_devices": self.affected_devices,
            "recommendation": self.recommendation,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "impact": self.impact,
            "references": self.references
        }


@dataclass
class CategoryAssessment:
    """Assessment result for a specific category"""
    category: AssessmentCategory
    score: float  # 0-100
    weight: float  # Percentage weight
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        """Calculate weighted score"""
        return self.score * self.weight

    @property
    def risk_level(self) -> RiskLevel:
        """Get risk level for this category"""
        return RiskLevel.from_score(100 - self.score)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "category": self.category.value,
            "score": round(self.score, 2),
            "weight": self.weight,
            "weighted_score": round(self.weighted_score, 2),
            "risk_level": self.risk_level.value,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
            "details": self.details
        }


@dataclass
class DeviceRiskProfile:
    """Risk profile for individual device"""
    ip: str
    hostname: str = ""
    device_type: str = ""
    vendor: str = ""
    model: str = ""
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO
    criticality_multiplier: float = 1.0
    findings: List[Finding] = field(default_factory=list)
    protection_level: Optional[int] = None
    firmware_age_years: Optional[float] = None
    firmware_version: Optional[str] = None
    cve_count: int = 0
    open_ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_critical_device(self) -> bool:
        """Check if this is a critical device"""
        critical_types = ["Safety PLC", "Emergency Shutdown", "SCADA"]
        return any(ct in self.device_type for ct in critical_types)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "model": self.model,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
            "criticality_multiplier": self.criticality_multiplier,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "protection_level": self.protection_level,
            "firmware_age_years": self.firmware_age_years,
            "firmware_version": self.firmware_version,
            "cve_count": self.cve_count,
            "open_ports": self.open_ports,
            "protocols": self.protocols,
            "metadata": self.metadata,
            "is_critical": self.is_critical_device
        }


@dataclass
class ComplianceStatus:
    """Compliance framework status"""
    framework: str  # "IEC 62443", "NIST CSF", etc.
    overall_compliance: float  # 0-100 percentage
    requirements_met: int
    requirements_total: int
    security_level: Optional[str] = None  # For IEC 62443: SL0-4
    maturity_tier: Optional[int] = None   # For NIST CSF: Tier 1-4
    gaps: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "framework": self.framework,
            "overall_compliance": round(self.overall_compliance, 2),
            "requirements_met": self.requirements_met,
            "requirements_total": self.requirements_total,
            "security_level": self.security_level,
            "maturity_tier": self.maturity_tier,
            "gaps": self.gaps,
            "details": self.details
        }


@dataclass
class RiskMatrix:
    """Risk distribution matrix"""
    by_zone: Dict[str, float] = field(default_factory=dict)
    by_device_type: Dict[str, float] = field(default_factory=dict)
    by_protocol: Dict[str, float] = field(default_factory=dict)
    by_vendor: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "by_zone": self.by_zone,
            "by_device_type": self.by_device_type,
            "by_protocol": self.by_protocol,
            "by_vendor": self.by_vendor
        }


@dataclass
class ActionItem:
    """Remediation action item"""
    priority: str  # "IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"
    title: str
    description: str
    affected_devices: List[str] = field(default_factory=list)
    estimated_effort: str = ""  # "Hours", "Days", "Weeks"
    timeline: str = ""  # "24h", "1 week", "1 month", "3 months"

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "affected_devices": self.affected_devices,
            "estimated_effort": self.estimated_effort,
            "timeline": self.timeline
        }


@dataclass
class RiskAssessmentReport:
    """Complete risk assessment report"""
    # Overview
    scan_timestamp: datetime
    report_id: str
    total_devices: int
    overall_risk_score: float
    overall_risk_level: RiskLevel

    # Category assessments
    network_assessment: CategoryAssessment
    device_assessment: CategoryAssessment
    vulnerability_assessment: CategoryAssessment
    compliance_assessment: CategoryAssessment

    # Device details
    device_profiles: List[DeviceRiskProfile] = field(default_factory=list)
    critical_devices: List[DeviceRiskProfile] = field(default_factory=list)

    # Findings summary
    critical_findings: List[Finding] = field(default_factory=list)
    high_findings: List[Finding] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)

    # Compliance
    compliance_status: List[ComplianceStatus] = field(default_factory=list)

    # Risk matrix
    risk_matrix: Optional[RiskMatrix] = None

    # Action plan
    immediate_actions: List[ActionItem] = field(default_factory=list)
    short_term_actions: List[ActionItem] = field(default_factory=list)
    medium_term_actions: List[ActionItem] = field(default_factory=list)
    long_term_actions: List[ActionItem] = field(default_factory=list)

    # Metadata
    scan_scope: str = ""
    methodology: str = ""
    tools_used: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Total number of findings"""
        return len(self.all_findings)

    @property
    def critical_count(self) -> int:
        """Count of critical findings"""
        return len(self.critical_findings)

    @property
    def high_count(self) -> int:
        """Count of high findings"""
        return len(self.high_findings)

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "overview": {
                "scan_timestamp": self.scan_timestamp.isoformat(),
                "report_id": self.report_id,
                "total_devices": self.total_devices,
                "overall_risk_score": round(self.overall_risk_score, 2),
                "overall_risk_level": self.overall_risk_level.value,
                "total_findings": self.total_findings,
                "critical_count": self.critical_count,
                "high_count": self.high_count
            },
            "assessments": {
                "network": self.network_assessment.to_dict(),
                "device": self.device_assessment.to_dict(),
                "vulnerability": self.vulnerability_assessment.to_dict(),
                "compliance": self.compliance_assessment.to_dict()
            },
            "device_profiles": [d.to_dict() for d in self.device_profiles],
            "critical_devices": [d.to_dict() for d in self.critical_devices],
            "findings": {
                "critical": [f.to_dict() for f in self.critical_findings],
                "high": [f.to_dict() for f in self.high_findings],
                "all": [f.to_dict() for f in self.all_findings]
            },
            "compliance": [c.to_dict() for c in self.compliance_status],
            "risk_matrix": self.risk_matrix.to_dict() if self.risk_matrix else {},
            "action_plan": {
                "immediate": [a.to_dict() for a in self.immediate_actions],
                "short_term": [a.to_dict() for a in self.short_term_actions],
                "medium_term": [a.to_dict() for a in self.medium_term_actions],
                "long_term": [a.to_dict() for a in self.long_term_actions]
            },
            "metadata": {
                "scan_scope": self.scan_scope,
                "methodology": self.methodology,
                "tools_used": self.tools_used
            }
        }
