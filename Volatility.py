#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Set, Tuple, Dict, Any

# CW2 Exercise 2 - Task-2 (Automating volatility2) - Memory Forensic

def run(cmd, timeout: int = 600) -> Tuple[int, str]:
    prcs = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout
    )
    return prcs.returncode, prcs.stdout

def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

def parse_pids_vol2(text: str) -> Set[int]:
    """
    Volatility2 pslist/psscan output typically looks like:
      Offset(V)          Name        PID   PPID ...
      0x81f3c020         csrss.exe    712   676  ...

    Therefore:
      cols[0]=offset, cols[1]=name, cols[2]=PID
    """
    pids: Set[int] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Offset") or line.startswith("----"):
            continue

        cols = re.split(r"\s+", line)
        if len(cols) >= 3 and cols[2].isdigit():
            pids.add(int(cols[2]))
    return pids

def pick_profile_from_imageinfo(imageinfo_out: str) -> Optional[str]:
    m = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)", imageinfo_out)
    if not m:
        return None

    first = m.group(1).split(",")[0].strip()
    first = re.split(r"\s+", first)[0].strip()
    return first if first else None

def main() -> None:
    ap = argparse.ArgumentParser(
        description="CW2 Ex2 Project 1 - Volatility2 triage automation (pslist/psscan hidden PID detection)"
    )
    ap.add_argument("--mem", required=True, help="Path to memory dump (e.g., win.mem)")
    ap.add_argument("--outdir", default=None, help="Output directory (default: ./outputs_<epoch>)")
    ap.add_argument("--vol", default="volatility2", help="Volatility2 executable (default: volatility2)")
    ap.add_argument("--profile", default=None, help="Volatility profile (if omitted, auto-detect via imageinfo)")
    args = ap.parse_args()

    mem = Path(args.mem).resolve()
    if not mem.exists():
        print(f"ERROR: memory dump not found: {mem}", file=sys.stderr)
        sys.exit(2)

    outdir = Path(args.outdir) if args.outdir else Path(f"outputs_{int(time.time())}")
    outdir = outdir.resolve()
    raw_dir = outdir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    imageinfo_cmd = [args.vol, "-f", str(mem), "imageinfo"]
    img_code, imageinfo_out = run(imageinfo_cmd)
    write_text(raw_dir / "imageinfo.txt", imageinfo_out)

    profile = args.profile or pick_profile_from_imageinfo(imageinfo_out)
    if not profile:
        print(
            "ERROR: Could not auto-detect profile from imageinfo. "
            "Re-run with --profile <ProfileName> (e.g., WinXPSP2x86).",
            file=sys.stderr
        )
        sys.exit(3)

    plugins = {
        "pslist": "pslist",
        "psscan": "psscan",
        "connscan": "connscan",
        "sockets": "sockets",
        "loggedin": "loggedin",
        "consoles": "consoles",
        "cmdscan": "cmdscan",
    }

    results: Dict[str, Dict[str, Any]] = {
        "imageinfo": {
            "cmd": " ".join(imageinfo_cmd),
            "exit_code": img_code,
            "raw_file": "imageinfo.txt"
        }
    }

    for key, plug in plugins.items():
        cmd = [args.vol, "-f", str(mem), f"--profile={profile}", plug]
        c, out = run(cmd)
        write_text(raw_dir / f"{key}.txt", out)
        results[key] = {"cmd": " ".join(cmd), "exit_code": c, "raw_file": f"{key}.txt"}

    pslist_text = read_text(raw_dir / "pslist.txt")
    psscan_text = read_text(raw_dir / "psscan.txt")
    pslist_pids = parse_pids_vol2(pslist_text)
    psscan_pids = parse_pids_vol2(psscan_text)
    hidden_pids = sorted(psscan_pids - pslist_pids)

    summary = {
        "memory_dump": str(mem),
        "profile_used": profile,
        "hidden_pids_psscan_not_pslist": hidden_pids,
        "counts": {
            "pslist_pids": len(pslist_pids),
            "psscan_pids": len(psscan_pids),
            "hidden_pids": len(hidden_pids),
        },
        "commands": results,
    }
    write_text(outdir / "summary.json", json.dumps(summary, indent=2))

    report = []
    report.append("VOLTRIAGE2 REPORT (CW2 Exercise 2 - Project 1)\n")
    report.append(f"Memory dump: {mem}\n")
    report.append(f"Profile used: {profile}\n")

    report.append("\n[1] imageinfo (profile/OS inference)\n")
    report.append(imageinfo_out)

    report.append("\n[2] pslist\n")
    report.append(pslist_text)

    report.append("\n[3] psscan\n")
    report.append(psscan_text)

    report.append("\n[4] Hidden/suspicious PIDs (psscan but not pslist)\n")
    report.append(", ".join(map(str, hidden_pids)) + "\n" if hidden_pids else "None detected.\n")

    for section, fname in [
        ("[5] connscan", "connscan.txt"),
        ("[6] sockets", "sockets.txt"),
        ("[7] loggedin", "loggedin.txt"),
        ("[8] consoles", "consoles.txt"),
        ("[9] cmdscan", "cmdscan.txt"),
    ]:
        report.append(f"\n{section}\n")
        report.append(read_text(raw_dir / fname))

    write_text(outdir / "report.txt", "\n".join(report))

    print(f"Done.\nReport: {outdir / 'report.txt'}\nSummary: {outdir / 'summary.json'}\nRaw: {raw_dir}")

if __name__ == "__main__":
    main()
