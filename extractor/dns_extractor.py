#!/usr/bin/env python3
# - Label: --class, --subclass
# - Output: Class, Subclass, label("Class:Subclass")

import argparse
import os
import json
import numpy as np
import pandas as pd

STD_COLS = [
    "frame.time_epoch","ip.src","ipv6.src","dns.flags.response",
    "dns.qry.name","dns.qry.type","dns.resp.name","dns.resp.type",
    "dns.resp.ttl","dns.resp.len","dns.flags.rcode",   
    "dns.count.answers","dns.count.add_rr","udp.length","frame.len"
]

ALIASES = {
    "timestamp": "frame.time_epoch",
    "status_code": "dns.flags.rcode",
    "query_name": "dns.qry.name", "query_type": "dns.qry.type",
    "response_name": "dns.resp.name", "response_type": "dns.resp.type",
    "response_ttl": "dns.resp.ttl",
    "ip4_address": "ip.src", "ip6_address": "ipv6.src"
}

def load_taxonomy(tax_path: str):
    with open(tax_path, "r", encoding="utf-8") as f:
        tax = json.load(f)
    if not isinstance(tax, dict) or not tax:
        raise ValueError("taxonomy JSON must be a non-empty object")
    allowed_classes = list(tax.keys())
    per_class_subs = {}
    for klass, items in tax.items():
        subs = set()
        if isinstance(items, list):
            for it in items:
                sub = str(it.get("SubClass", klass)).strip()
                if sub:
                    subs.add(sub)
        per_class_subs[klass] = sorted(subs)
    return allowed_classes, per_class_subs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Input CSV (supports .gz)")
    ap.add_argument("--taxonomy", required=True, help="dns_attack_taxonomy.json (validation)")
    ap.add_argument("--class", dest="klass", required=True, help='e.g., "Benign" or "Flooding"')
    ap.add_argument("--subclass", required=True, help='e.g., "Benign", "Query Flooding", "Response Flooding", ...')
    ap.add_argument("--out", default="tmp/extracted.csv")
    ap.add_argument("--infer-response-from-rcode", action="store_true",
                    help="If dns.flags.response is missing, set response=1 where rcode exists.")
    args = ap.parse_args()


    allowed_classes, per_class_subs = load_taxonomy(args.taxonomy)
    klass = args.klass.strip()
    subclass = args.subclass.strip()

    if klass not in allowed_classes:
        raise SystemExit(f'Invalid --class "{klass}". Allowed: {allowed_classes}')
    allowed_subs = set(per_class_subs.get(klass, []))
    if subclass not in allowed_subs:
        raise SystemExit(
            f'Invalid --subclass "{subclass}" for class "{klass}". '
            f"Allowed: {sorted(allowed_subs)}"
        )

    df = pd.read_csv(args.input, low_memory=False, on_bad_lines="skip", compression="infer")
    df.columns = df.columns.str.strip()
    df = df.rename(columns=ALIASES)

    if "dns.flags.rcode" not in df.columns and "dns.rcode" in df.columns:
        df["dns.flags.rcode"] = df["dns.rcode"]

    if "dns.flags.response" not in df.columns:
        if args.infer_response_from_rcode and "dns.flags.rcode" in df.columns:
            df["dns.flags.response"] = (df["dns.flags.rcode"].notna()).astype(int)
        else:
            df["dns.flags.response"] = 0

    for c in STD_COLS:
        if c not in df.columns:
            df[c] = np.nan

    num_like = [
        "frame.time_epoch","dns.qry.type","dns.resp.type","dns.resp.ttl","dns.resp.len",
        "dns.flags.response","dns.flags.rcode","dns.count.answers","dns.count.add_rr",
        "udp.length","frame.len"
    ]
    for c in num_like:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="ignore") 

    out = df[STD_COLS].copy()
    out["Class"] = klass
    out["Subclass"] = subclass
    out["label"] = f"{klass}:{subclass}"

    if "frame.time_epoch" in out.columns:
        out = out.sort_values("frame.time_epoch", kind="mergesort")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out.to_csv(args.out, index=False)

    n = len(out)
    has_resp = int(out["dns.flags.response"].fillna(0).astype(int).sum())
    rcode_nonnull = int(out["dns.flags.rcode"].notna().sum())
    print(f"[ok] wrote {args.out}  rows={n}  class={klass}  subclass={subclass}")
    print(f"[info] resp_flag=1 rows={has_resp}  rcode_nonnull={rcode_nonnull}")

if __name__ == "__main__":
    main()
