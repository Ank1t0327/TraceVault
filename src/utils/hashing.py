import hashlib

def calculate_hashes(filepath):
    """Calculates SHA-256, SHA-1, and MD5 hashes for a given file."""
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()
    
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                sha1_hash.update(byte_block)
                md5_hash.update(byte_block)
                
        return {
            "SHA-256": sha256_hash.hexdigest(),
            "SHA-1": sha1_hash.hexdigest(),
            "MD5": md5_hash.hexdigest()
        }
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error hashing file: {e}")
        return None
