#!/usr/bin/env python3
"""
Parda CLI: The intelligent privacy veil for Cloud LLMs.
https://github.com/AlphaAI-dev/Parda
"""

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
for p in [SCRIPT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

import argparse
from parda_core.detectors import PardaDetector
from parda_core.masker import PardaMasker
from parda_core.vault import PardaSession


def banner():
    print("""
\033[1;34m===================================================================
  ____                 _         _    ___ 
 |  _ \ __ _ _ __   __| | __ _  / \  |_ _|
 | |_) / _` | '__| / _` |/ _` |/ _ \  | | 
 |  __/ (_| | |   | (_| | (_| / ___ \ | | 
 |_|   \__,_|_|    \__,_|\__,_/_/   \_\___|
  
  Intelligent Privacy Veil for Cloud LLMs (Gemini, ChatGPT, Claude)
  https://github.com/AlphaAI-dev/Parda
===================================================================\033[0m
""")


def cmd_scan(args):
    detector = PardaDetector()
    text = args.text
    if os.path.isfile(text):
        with open(text, "r", encoding="utf-8") as f:
            text = f.read()

    matches = detector.detect_all(text, scope=args.scope.upper())
    print(f"\n\033[1;32m[*] Parda Veil detected {len(matches)} confidential entities:\033[0m\n")
    print(f"{'TYPE':<20} | {'SCOPE':<8} | {'VALUE':<24} | {'METADATA'}")
    print("-" * 80)
    for m in matches:
        meta_str = ", ".join(f"{k}={v}" for k, v in m.metadata.items())
        print(f"{m.entity_type:<20} | {m.scope:<8} | {m.value:<24} | {meta_str}")
    print("-" * 80)


def cmd_mask(args):
    masker = PardaMasker()
    text = args.text
    if os.path.isfile(text):
        with open(text, "r", encoding="utf-8") as f:
            text = f.read()

    masked, vault, entities = masker.mask(
        text, strategy=args.strategy.upper(), scope=args.scope.upper()
    )
    print("\n\033[1;32m[*] Parda Sanitized Output:\033[0m")
    print("-" * 60)
    print(masked)
    print("-" * 60)
    print(f"\033[1;33m[!] Protected {len(entities)} sensitive items. Vault mapped {len(vault)} keys.\033[0m\n")


def cmd_web(args):
    import http.server
    import socketserver
    import webbrowser

    port = args.port or 8080
    web_dir = os.path.join(SCRIPT_DIR, "web")
    os.chdir(web_dir)

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        url = f"http://localhost:{port}"
        print(f"\n\033[1;32m[✓] Parda Web Interface running at: {url}\033[0m")
        print("Press Ctrl+C to stop.\n")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


def main():
    parser = argparse.ArgumentParser(
        description="Parda AI - Intelligent Privacy Veil for Cloud LLMs"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Scan text or file for PII and credentials")
    p_scan.add_argument("text", help="Text or file path")
    p_scan.add_argument("--scope", choices=["all", "global", "regional"], default="all")

    # Mask command
    p_mask = subparsers.add_parser("mask", help="Mask sensitive entities in text or file")
    p_mask.add_argument("text", help="Text or file path")
    p_mask.add_argument("--strategy", choices=["token", "blackout", "synthetic"], default="token")
    p_mask.add_argument("--scope", choices=["all", "global", "regional"], default="all")

    # Web command
    p_web = subparsers.add_parser("web", help="Launch interactive web interface")
    p_web.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    if not args.command:
        banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "mask":
        cmd_mask(args)
    elif args.command == "web":
        cmd_web(args)


if __name__ == "__main__":
    main()
