import os
from src.analyzers.fs_analyzer import FileSystemAnalyzer

def test_is_hidden():
    assert FileSystemAnalyzer.is_hidden('.hidden_file') == True
    assert FileSystemAnalyzer.is_hidden('normal_file.txt') == False

def test_is_suspicious_filename():
    assert FileSystemAnalyzer.is_suspicious_filename('malware.exe') == True
    assert FileSystemAnalyzer.is_suspicious_filename('test.txt.exe') == True
    assert FileSystemAnalyzer.is_suspicious_filename('report.pdf') == False
