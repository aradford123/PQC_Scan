#!/usr/bin/env python3
"""
analyze_pqc_trends.py

Simple analysis + plots for TLS / PQC scans.

- Scans a directory for *-tls_pqc_results.pkl
- Adds snapshot_date, host_only, aes_family, tls_group_norm, is_hybrid_pqc
- Prints:
  - AES-128 vs AES-256 breakdown per snapshot
  - TLS group breakdown per snapshot
  - Hybrid PQC group adoption over time
- Produces plots in a --plot-dir folder:
  - aes_adoption.png
  - tls_group_adoption.png
  - pqc_adoption.png
- With --html PATH, writes a self-contained HTML report instead of showing plots
"""

import argparse
import json
from datetime import date
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze TLS / PQC trends over time")
    p.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory containing *-tls_pqc_results.pkl files (default: ./data)",
    )
    p.add_argument(
        "--pattern",
        type=str,
        default="*-tls_pqc_results.pkl",
        help="Glob pattern for snapshot files (default: '*-tls_pqc_results.pkl')",
    )
    p.add_argument(
        "--plot-dir",
        type=Path,
        default=Path("plots"),
        help="Directory to save plots (default: ./plots)",
    )
    p.add_argument(
        "--html",
        type=Path,
        default=None,
        help="Write an HTML report to this path instead of showing plots",
    )
    return p.parse_args()


def classify_aes(ciphersuite: str) -> str:
    """Return AES-128 / AES-256 / Other/None based on ciphersuite name."""
    if not isinstance(ciphersuite, str):
        return "Other/None"
    cs = ciphersuite.upper()
    if "AES128" in cs or "AES_128" in cs:
        return "AES-128"
    if "AES256" in cs or "AES_256" in cs:
        return "AES-256"
    return "Other/None"


def normalize_group(row: pd.Series) -> str:
    """
    Normalise TLS group naming into a small set of categories.

    Prefers 'Group', falls back to 'TLS1.3_Group' if missing.
    """
    grp = row.get("Group", None)
    if (grp is None) or (not isinstance(grp, str)) or (grp.strip() == ""):
        grp = row.get("TLS1.3_Group", "")

    if not isinstance(grp, str):
        return "Unknown"

    g = grp.upper()

    if "X25519MLKEM768" in g:
        return "X25519+ML-KEM-768 (Hybrid PQC)"
    if "X25519" in g:
        return "X25519"
    if "PRIME256V1" in g or "SECP256R1" in g:
        return "P-256"
    if "SECP384R1" in g:
        return "P-384"
    if "SECP521R1" in g:
        return "P-521"
    if "ECDH" in g:
        return "ECDH-other"
    return "Unknown"


def load_snapshot(path: Path) -> pd.DataFrame:
    """
    Load a single snapshot file and add snapshot_date + host_only.
    Expects filenames like: YYYY-MM-DD-tls_pqc_results.pkl
    """
    df = pd.read_pickle(path)

    # derive snapshot date from filename
    name = path.name
    # e.g. "2025-07-09-tls_pqc_results.pkl" -> "2025-07-09"
    date_str = name.split("-tls_pqc_results.pkl")[0]
    snapshot_date = pd.to_datetime(date_str, errors="coerce")

    df["snapshot_date"] = snapshot_date
    df["host_only"] = df["Host"].str.replace(r":\d+$", "", regex=True)

    # AES family
    df["aes_family"] = df["Ciphersuite"].apply(classify_aes)

    # TLS group normalisation
    df["tls_group_norm"] = df.apply(normalize_group, axis=1)
    df["is_hybrid_pqc"] = df["tls_group_norm"].str.contains("HYBRID PQC", case=False)

    return df


def summarise_aes(df_all: pd.DataFrame) -> pd.DataFrame:
    print("\n=== AES-128 vs AES-256 adoption over time ===")

    # dedupe host per snapshot to avoid double counting
    base = (
        df_all
        .sort_values(["snapshot_date", "host_only"])
        .drop_duplicates(subset=["snapshot_date", "host_only"])
    )

    aes_ts = (
        base
        .groupby(["snapshot_date", "aes_family"])["host_only"]
        .nunique()
        .reset_index(name="n_hosts")
    )

    # percentage per snapshot
    aes_ts = (
        aes_ts
        .groupby("snapshot_date")
        .apply(lambda g: g.assign(pct=g["n_hosts"] / g["n_hosts"].sum() * 100))
        .reset_index(drop=True)
    )

    aes_ts = aes_ts.sort_values(["snapshot_date", "aes_family"])

    for date, group in aes_ts.groupby("snapshot_date"):
        print(f"\nSnapshot: {date.date()}")
        for _, row in group.iterrows():
            fam = row["aes_family"]
            n = int(row["n_hosts"])
            pct = row["pct"]
            print(f"  {fam:10s}: {n:4d} hosts ({pct:5.1f}%)")

    return aes_ts


def summarise_groups(df_all: pd.DataFrame) -> pd.DataFrame:
    print("\n=== TLS group adoption over time ===")

    base = (
        df_all
        .sort_values(["snapshot_date", "host_only"])
        .drop_duplicates(subset=["snapshot_date", "host_only"])
    )

    grp_ts = (
        base
        .groupby(["snapshot_date", "tls_group_norm"])["host_only"]
        .nunique()
        .reset_index(name="n_hosts")
    )

    grp_ts = (
        grp_ts
        .groupby("snapshot_date")
        .apply(lambda g: g.assign(pct=g["n_hosts"] / g["n_hosts"].sum() * 100))
        .reset_index(drop=True)
    )

    grp_ts = grp_ts.sort_values(["snapshot_date", "tls_group_norm"])

    for date, group in grp_ts.groupby("snapshot_date"):
        print(f"\nSnapshot: {date.date()}")
        for _, row in group.iterrows():
            gname = row["tls_group_norm"]
            n = int(row["n_hosts"])
            pct = row["pct"]
            print(f"  {gname:35s}: {n:4d} hosts ({pct:5.1f}%)")

    return grp_ts


def summarise_pqc(df_all: pd.DataFrame) -> pd.DataFrame:
    print("\n=== Hybrid PQC group adoption (X25519+ML-KEM-768) ===")

    dedup = (
        df_all
        .sort_values(["snapshot_date", "host_only"])
        .drop_duplicates(subset=["snapshot_date", "host_only"])
    )

    pqc_ts = (
        dedup
        .groupby("snapshot_date")["is_hybrid_pqc"]
        .agg(
            pqc_hosts="sum",
            total_hosts="count",
        )
        .reset_index()
    )
    pqc_ts["pct_pqc"] = pqc_ts["pqc_hosts"] / pqc_ts["total_hosts"] * 100.0

    for _, row in pqc_ts.sort_values("snapshot_date").iterrows():
        date = row["snapshot_date"].date()
        pqc_hosts = int(row["pqc_hosts"])
        total = int(row["total_hosts"])
        pct = row["pct_pqc"]
        print(f"{date}: {pqc_hosts:4d}/{total:4d} hosts ({pct:5.1f}%) using hybrid PQC group")

    return pqc_ts


# --------------------------- plotting helpers ---------------------------

def plot_aes(aes_ts: pd.DataFrame, plot_dir: Path) -> None:
    """Line chart: % of hosts using AES-128 vs AES-256 over time."""
    plot_dir.mkdir(parents=True, exist_ok=True)

    pivot = (
        aes_ts
        .pivot(index="snapshot_date", columns="aes_family", values="pct")
        .fillna(0)
        .sort_index()
    )

    fig, ax = plt.subplots()
    for fam in ["AES-128", "AES-256"]:
        if fam in pivot.columns:
            ax.plot(pivot.index, pivot[fam], label=fam)

    ax.set_xlabel("Snapshot date")
    ax.set_ylabel("% of hosts")
    ax.set_title("AES family adoption over time")
    ax.legend()
    fig.autofmt_xdate()
    plt.tight_layout()
    #out_path = plot_dir / "aes_adoption.png"
    #fig.savefig(out_path, dpi=150)
    #plt.close(fig)
    plt.show()
    #print(f"Saved AES adoption plot -> {out_path}")


def plot_tls_groups(grp_ts: pd.DataFrame, plot_dir: Path) -> None:
    """Line chart: % of hosts by TLS group (key exchange) over time."""
    plot_dir.mkdir(parents=True, exist_ok=True)

    pivot = (
        grp_ts
        .pivot(index="snapshot_date", columns="tls_group_norm", values="pct")
        .fillna(0)
        .sort_index()
    )

    # focus on main groups; everything else is ignored in the plot
    interesting = [
        "X25519",
        "P-256",
        "X25519+ML-KEM-768 (Hybrid PQC)",
    ]

    fig, ax = plt.subplots()
    for gname in interesting:
        if gname in pivot.columns:
            ax.plot(pivot.index, pivot[gname], label=gname)

    ax.set_xlabel("Snapshot date")
    ax.set_ylabel("% of hosts")
    ax.set_title("TLS key-exchange group adoption over time")
    ax.legend()
    fig.autofmt_xdate()
    plt.tight_layout()
    #out_path = plot_dir / "tls_group_adoption.png"
    #fig.savefig(out_path, dpi=150)
    #plt.close(fig)
    #print(f"Saved TLS group adoption plot -> {out_path}")
    plt.show()


def plot_pqc(pqc_ts: pd.DataFrame, plot_dir: Path) -> None:
    """Line chart: % of hosts using hybrid PQC groups over time."""
    plot_dir.mkdir(parents=True, exist_ok=True)

    pqc_ts = pqc_ts.sort_values("snapshot_date")

    fig, ax = plt.subplots()
    ax.plot(pqc_ts["snapshot_date"], pqc_ts["pct_pqc"])

    ax.set_xlabel("Snapshot date")
    ax.set_ylabel("% of hosts using hybrid PQC")
    ax.set_title("Hybrid PQC (X25519+ML-KEM-768) adoption over time")
    fig.autofmt_xdate()
    plt.tight_layout()
    #out_path = plot_dir / "pqc_adoption.png"
    #fig.savefig(out_path, dpi=150)
    #plt.close(fig)
    #print(f"Saved PQC adoption plot -> {out_path}")
    plt.show()


# ----------------------------- HTML report ------------------------------

TEMPLATE_PATH = Path(__file__).with_name("report_template.html")
OTHER_GROUPS = {"P-384", "P-521", "ECDH-other", "Unknown"}


def _pct(n: int, d: int) -> float:
    return round(n / d * 100.0, 2) if d else 0.0


def build_report_data(df_all: pd.DataFrame) -> dict:
    """Per-snapshot shares (of reachable hosts), last-scan changes and the host register."""
    df = (
        df_all
        .drop_duplicates(subset=["snapshot_date", "host_only"])
        .assign(
            reachable=lambda d: d["Error"].fillna("").astype(str).str.strip() == "",
            date=lambda d: d["snapshot_date"].dt.strftime("%Y-%m-%d"),
        )
    )

    snapshots = []
    for snap_date, g in df.groupby("date", sort=True):
        r = g[g["reachable"]]
        n = len(r)
        groups = r["tls_group_norm"]
        snapshots.append({
            "date": snap_date,
            "targets": len(g),
            "reachable": n,
            "unreachable": len(g) - n,
            "pqc": int(r["is_hybrid_pqc"].sum()),
            "pqc_pct": _pct(int(r["is_hybrid_pqc"].sum()), n),
            "g_pqc": _pct(int(r["is_hybrid_pqc"].sum()), n),
            "g_x25519": _pct(int((groups == "X25519").sum()), n),
            "g_p256": _pct(int((groups == "P-256").sum()), n),
            "g_other": _pct(int(groups.isin(OTHER_GROUPS).sum()), n),
            "tls13_pct": _pct(int((r["Version"] == "TLSv1.3").sum()), n),
            "tls12_pct": _pct(int((r["Version"] == "TLSv1.2").sum()), n),
            "aes128_pct": _pct(int((r["aes_family"] == "AES-128").sum()), n),
            "aes256_pct": _pct(int((r["aes_family"] == "AES-256").sum()), n),
            "aes_other_pct": _pct(int((r["aes_family"] == "Other/None").sum()), n),
        })

    dates = [s["date"] for s in snapshots]
    pqc_by_date = {
        d: set(g.loc[g["reachable"] & g["is_hybrid_pqc"], "host_only"])
        for d, g in df.groupby("date")
    }
    last_d = dates[-1]
    prev_d = dates[-2] if len(dates) > 1 else last_d
    changes = {
        "gained": sorted(pqc_by_date[last_d] - pqc_by_date[prev_d]),
        "lost": sorted(pqc_by_date[prev_d] - pqc_by_date[last_d]),
    }

    # first snapshot each host negotiated hybrid PQC
    pqc_since = (
        df[df["reachable"] & df["is_hybrid_pqc"]]
        .groupby("host_only")["date"].min()
        .to_dict()
    )

    latest = df[df["date"] == last_d].sort_values("host_only")
    hosts = []
    for _, row in latest.iterrows():
        if not row["reachable"]:
            status = "Unreachable"
        elif row["is_hybrid_pqc"]:
            status = "Hybrid PQC"
        else:
            status = "Classical"
        group = row.get("Group") or row.get("TLS1.3_Group") or ""
        hosts.append({
            "host": row["host_only"],
            "status": status,
            "group": str(group).strip(),
            "version": row.get("Version") or "",
            "cipher": row.get("Ciphersuite") or "",
            "sig": row.get("Signature type") or "",
            "since": pqc_since.get(row["host_only"], "") if status == "Hybrid PQC" else "",
        })

    return {
        "generated": date.today().isoformat(),
        "n_targets": int(latest["host_only"].nunique()),
        "snapshots": snapshots,
        "changes": changes,
        "hosts": hosts,
    }


def write_html_report(df_all: pd.DataFrame, out_path: Path) -> None:
    data = build_report_data(df_all)
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    html = TEMPLATE_PATH.read_text().replace("/*__REPORT_DATA__*/null", payload)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    print(f"\nWrote HTML report -> {out_path}")


# ------------------------------- main -----------------------------------

def main() -> None:
    args = parse_args()

    files = sorted(args.data_dir.glob(args.pattern))
    if not files:
        raise SystemExit(f"No files matching {args.pattern!r} found in {args.data_dir}")

    print(f"Found {len(files)} snapshot file(s):")
    for f in files:
        print(f"  - {f}")

    df_list = [load_snapshot(p) for p in files]
    df_all = pd.concat(df_list, ignore_index=True)

    # Basic sanity check
    if df_all["snapshot_date"].isna().any():
        print("\n[WARN] Some snapshot_date values could not be parsed from filenames.")

    aes_ts = summarise_aes(df_all)
    grp_ts = summarise_groups(df_all)
    pqc_ts = summarise_pqc(df_all)

    if args.html:
        write_html_report(df_all, args.html)
        return

    # plots
    plot_aes(aes_ts, args.plot_dir)
    plot_tls_groups(grp_ts, args.plot_dir)
    plot_pqc(pqc_ts, args.plot_dir)


if __name__ == "__main__":
    main()

