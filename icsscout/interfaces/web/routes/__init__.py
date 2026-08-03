"""
Web routes for ICSScout web interface
"""

from .risk_assessment_routes import setup_risk_assessment_routes
from .ids_offline_routes import setup_ids_offline_routes

__all__ = ['setup_risk_assessment_routes', 'setup_ids_offline_routes']
