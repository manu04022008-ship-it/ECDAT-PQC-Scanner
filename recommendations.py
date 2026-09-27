PQC_MAPPING = {
    "RSA": {
        "replacement": "ML-KEM (Kyber) or Hybrid X25519+Kyber",
        "latency": "Low Impact",
        "cost": "Medium"
    },
    "3DES": {
        "replacement": "AES-256-GCM",
        "latency": "None",
        "cost": "Low"
    },
    "AES-ECB": {
        "replacement": "AES-256-GCM",
        "latency": "None",
        "cost": "Low"
    },
    "MD5": {
        "replacement": "SHA-256 / SHA-3",
        "latency": "None",
        "cost": "Low"
    },
    "SHA1": {
        "replacement": "SHA-256 / SHA-3",
        "latency": "None",
        "cost": "Low"
    },
    "SSLv3": {
        "replacement": "TLS 1.3 with Hybrid PQC Key Exchange",
        "latency": "Low Impact",
        "cost": "Medium"
    }
}

def get_recommendation(algorithm):
    for key, data in PQC_MAPPING.items():
        if key in algorithm:
            return data
    return {"replacement": "Review algorithm specification", "latency": "N/A", "cost": "N/A"}