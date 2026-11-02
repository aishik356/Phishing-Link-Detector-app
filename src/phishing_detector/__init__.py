"""Phishing link detector application."""

from .analyzer import AnalysisResult, Finding, analyze_url

__all__ = ["AnalysisResult", "Finding", "analyze_url"]
