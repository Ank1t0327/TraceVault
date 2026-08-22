import hashlib

def calculate_hashes(filepath, chunk_size=8192):
    """Calculate MD5, SHA-1, and SHA-256 hashes for a given file."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }
    except FileNotFoundError:
        return None

def verify_hash(filepath, expected_hash, algorithm="sha256"):
    """Verify if a file matches the expected hash."""
    hashes = calculate_hashes(filepath)
    if hashes is None:
        return False
    return hashes.get(algorithm.lower()) == expected_hash.lower()
