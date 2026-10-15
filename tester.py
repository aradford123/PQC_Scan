#!/usr/bin/env python

import subprocess
import re
import pandas as pd
from data.targets import targets


fields = [
    ("Protocol version", r"Protocol version: ([^\n]+)"),
    ("Ciphersuite", r"Ciphersuite: ([^\n]+)"),
    ("Peer certificate", r"Peer certificate: ([^\n]+)"),
    ("Hash used", r"Hash used: ([^\n]+)"),
    ("Signature type", r"Signature type: ([^\n]+)"),
    ("Peer Temp Key", r"Peer Temp Key: ([^\n]+)"),
    ("Negotiated TLS1.3 group", r"Negotiated TLS1\.3 group: ([^\n]+)"),
]

def test_tls_fields(host, port=443):
    print(f"++{host}")
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-brief"
    ]
    results = {"Host": f"{host}:{port}"}
    try:
        proc = subprocess.run(cmd, input=b'', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        output = proc.stdout.decode(errors="replace")

        # Look for common handshake failures or errors in output
        if "error" in output.lower() or "unable to" in output.lower() or "connect:" in output.lower():
            # Collect a reasonable error message from the output
            error_lines = [line for line in output.splitlines() if "error" in line.lower() or "unable to" in line.lower() or "connect:" in line.lower()]
            results["Error"] = " | ".join(error_lines) if error_lines else "Handshake or connection error"
            # Fill all other fields as blank
            for label, _ in fields:
                results[label] = ""
            results["Group"] = ""
            return results

        # Extract all fields
        for label, regex in fields:
            match = re.search(regex, output)
            results[label] = match.group(1).strip() if match else ""

        # 'Group' logic: prefer Negotiated TLS1.3 group, then Peer Temp Key
        results["Group"] = results["Negotiated TLS1.3 group"] or results["Peer Temp Key"]
        results["Error"] = ""
        return results

    except subprocess.TimeoutExpired:
        for label, _ in fields:
            results[label] = ""
        results["Group"] = ""
        results["Error"] = "Timeout"
        return results
    except Exception as e:
        for label, _ in fields:
            results[label] = ""
        results["Group"] = ""
        results["Error"] = str(e)
        return results

if __name__ == "__main__":
    rows = []
    for host, port in targets:
        rows.append(test_tls_fields(host, port))

    df = pd.DataFrame(rows)
    df.rename(columns={"Negotiated TLS1.3 group": "TLS1.3_Group",
                       "Hash used" : "Hash",
                       "Protocol version" : "Version",
                       "Temp Key": "TmpKey"}, inplace=True)
    print(df)
    from datetime import date

    today_str = date.today().strftime("%Y-%m-%d")

    df.to_pickle(f'data/{today_str}-tls_pqc_results.pkl')
