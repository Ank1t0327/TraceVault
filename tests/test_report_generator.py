import os
import json
import pytest
from src.reporting.report_generator import ReportGenerator, ReportData

def test_report_data_defaults():
    data = ReportData(case_id="CASE-9999", investigator="Test Investigator")
    assert data.case_id == "CASE-9999"
    assert data.investigator == "Test Investigator"
    assert "CRITICAL" in data.findings
    assert len(data.timeline) > 0
    assert len(data.iocs) > 0
    assert "sequence of failed authentication" in data.summary

def test_generate_json(tmp_path):
    out_file = str(tmp_path / "report.json")
    generator = ReportGenerator(ReportData(case_id="CASE-123"))
    res_path = generator.generate_json(out_file)
    assert os.path.exists(res_path)
    
    with open(res_path, "r", encoding="utf-8") as f:
        content = json.load(f)
    assert content["case_information"]["case_id"] == "CASE-123"
    assert "findings" in content
    assert "iocs" in content

def test_generate_html(tmp_path):
    out_file = str(tmp_path / "report.html")
    generator = ReportGenerator(ReportData(case_id="CASE-123"))
    res_path = generator.generate_html(out_file)
    assert os.path.exists(res_path)
    
    with open(res_path, "r", encoding="utf-8") as f:
        html = f.read()
    assert "<title>TraceVault Forensic Report - CASE-123</title>" in html
    assert "Executive Summary" in html
    assert "Chronological Timeline" in html
    assert "Indicators of Compromise" in html
