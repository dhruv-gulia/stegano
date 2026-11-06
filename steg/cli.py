"""Command line interface: encode, decode, detect, and measure."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from PIL import Image

from .analysis import analyze
from .core import StegError, capacity_bytes, decode, encode
from .metrics import mse, psnr


def _password(value: str | None) -> str:
    return value if value is not None else getpass.getpass("Password: ")


def _run_encode(args) -> int:
    try:
        message = Path(args.message_file).read_bytes() if args.message_file else args.message
    except OSError as exc:
        print(f"error: cannot read message file: {exc}", file=sys.stderr)
        return 1
    output = Path(args.output or f"{Path(args.image).stem}-stego.{args.format}")
    try:
        data, stats = encode(args.image, message, _password(args.password), fmt=args.format)
    except StegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    output.write_bytes(data)
    print(f"wrote {output}")
    print(f"capacity: {stats['capacity_bytes']} bytes | used: {stats['fill_percent']}% | PSNR: {stats['psnr_db']} dB")
    return 0


def _run_decode(args) -> int:
    try:
        message = decode(args.image, _password(args.password))
    except StegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_bytes(message)
        print(f"wrote {args.output} ({len(message)} bytes)")
    else:
        try:
            print(message.decode("utf-8"))
        except UnicodeDecodeError:
            print("error: message is binary, use -o FILE", file=sys.stderr)
            return 1
    return 0


def _run_metrics(args) -> int:
    try:
        original = Image.open(args.original).convert("RGB")
        stego = Image.open(args.stego).convert("RGB")
    except (OSError, ValueError):
        print("error: cannot read one of the images", file=sys.stderr)
        return 1
    if original.size != stego.size:
        print("error: images must have the same dimensions", file=sys.stderr)
        return 1
    print(f"capacity:   {capacity_bytes(original)} bytes")
    print(f"MSE:        {mse(original, stego):.4f}")
    print(f"PSNR:       {psnr(original, stego):.2f} dB")
    return 0


def _run_detect(args) -> int:
    try:
        report = analyze(args.image)
    except StegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"chi-square: {report['chi_square']} (df {report['dof']})")
    print(f"p-value:    {report['p_value']}")
    print(f"legacy:     {'STEG1' if report['legacy_header'] else 'none'}")
    print(report["verdict"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="steg", description="LSB image steganography with AES-GCM encryption")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="hide a message in an image")
    enc.add_argument("image", help="cover image (PNG or BMP recommended)")
    enc.add_argument("-m", "--message", default="", help="message text")
    enc.add_argument("-f", "--message-file", help="read message bytes from a file")
    enc.add_argument("-p", "--password", help="password (prompted if omitted)")
    enc.add_argument("-o", "--output", help="output path")
    enc.add_argument("--format", choices=["png", "bmp"], default="png", help="output format (default: png)")
    enc.set_defaults(func=_run_encode)

    dec = sub.add_parser("decode", help="extract a hidden message")
    dec.add_argument("image", help="stego image (PNG or BMP)")
    dec.add_argument("-p", "--password", help="password (prompted if omitted)")
    dec.add_argument("-o", "--output", help="write raw bytes to a file")
    dec.set_defaults(func=_run_decode)

    det = sub.add_parser("detect", help="run the chi-square steganalysis test")
    det.add_argument("image", help="image to analyse")
    det.set_defaults(func=_run_detect)

    met = sub.add_parser("metrics", help="compare cover and stego images")
    met.add_argument("original")
    met.add_argument("stego")
    met.set_defaults(func=_run_metrics)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "encode" and not args.message_file and not args.message:
        print("error: provide -m or -f", file=sys.stderr)
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
