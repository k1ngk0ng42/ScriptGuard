# scriptguard/core/mitre/rules.py

from typing import Dict, List


MITRE_TECHNIQUES: Dict[str, Dict] = {
    # ================= Execution =================
    "T1059.001": {
        "name": "PowerShell",
        "keywords": ["powershell", "invoke-expression", "iex", "pscommand"]
    },
    "T1059.007": {
        "name": "JavaScript",
        "keywords": ["eval(", "function", "document.", "window."]
    },
    "T1059.005": {
        "name": "Visual Basic",
        "keywords": ["createobject", "wscript", "chr(", "chrw("]
    },

    # ================= Initial Access =================
    "T1566.001": {
        "name": "Phishing Attachment",
        "keywords": ["macro", "attachment", "invoice", "docm", "xlsm"]
    },
    "T1566.002": {
        "name": "Phishing Link",
        "keywords": ["click", "verify", "login", "update account"]
    },

    # ================= Defense Evasion =================
    "T1027": {
        "name": "Obfuscated Files or Information",
        "keywords": ["base64", "xor", "rot", "encode", "obfusc"]
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "keywords": ["decode", "frombase64", "unescape"]
    },
    "T1497.001": {
        "name": "System Checks",
        "keywords": ["sandbox", "vmware", "virtualbox", "debug"]
    },

    # ================= Command and Control =================
    "T1071.001": {
        "name": "Web Protocols",
        "keywords": ["http://", "https://", "user-agent", "post", "get"]
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "keywords": ["download", "wget", "curl", "bitsadmin"]
    },

    # ================= Persistence =================
    "T1547.001": {
        "name": "Registry Run Keys",
        "keywords": ["run\\", "runonce", "currentversion"]
    },

    # ================= Credential Access =================
    "T1555": {
        "name": "Credentials from Password Stores",
        "keywords": ["password", "credential", "cred"]
    },

    # ================= Discovery =================
    "T1082": {
        "name": "System Information Discovery",
        "keywords": ["hostname", "whoami", "systeminfo", "osversion"]
    },
    "T1057": {
        "name": "Process Discovery",
        "keywords": ["tasklist", "get-process", "ps aux"]
    },

    # ================= Impact =================
    "T1486": {
        "name": "Data Encrypted for Impact",
        "keywords": ["ransom", "encrypt", "decrypt", "aes", "rsa"]
    },
}


def classify_mitre(code: str) -> List[Dict[str, str]]:
    """
    Классификация кода по MITRE ATT&CK.

    Возвращает список словарей:
    [
        {
            "id": "T1059.001",
            "name": "PowerShell"
        },
        ...
    ]
    """
    text = code.lower()
    results = []

    for tid, info in MITRE_TECHNIQUES.items():
        keywords = info["keywords"]

        if any(k in text for k in keywords):
            results.append({
                "id": tid,
                "name": info["name"]
            })

    return results
