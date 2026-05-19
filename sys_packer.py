#!/usr/bin/env python3
"""Desempacotador e empacotador simples para arquivos .sys no formato usado por ftinfo.sys.

Formato esperado:
- 4 bytes: versão (little-endian, uint32)
- 4 bytes: tamanho do payload (little-endian, uint32)
- N bytes: payload
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

HEADER_STRUCT = struct.Struct("<II")


def unpack_sys(input_file: Path, output_file: Path) -> None:
    data = input_file.read_bytes()
    if len(data) < HEADER_STRUCT.size:
        raise ValueError("Arquivo muito pequeno para conter cabeçalho válido.")

    version, payload_size = HEADER_STRUCT.unpack_from(data, 0)
    payload_plus_footer = data[HEADER_STRUCT.size :]

    if len(payload_plus_footer) < payload_size:
        raise ValueError("Arquivo truncado: payload menor que o informado no cabeçalho.")

    payload = payload_plus_footer[:payload_size]
    footer = payload_plus_footer[payload_size:]

    if footer not in (b"", b"\x00\x00\x00\x00"):
        raise ValueError("Rodapé inesperado (esperado vazio ou 4 bytes nulos).")

    if payload_size != len(payload):
        raise ValueError(
            f"Tamanho inconsistente: cabeçalho={payload_size}, real={len(payload)}"
        )

    output_file.write_bytes(payload)
    print(f"[OK] Desempacotado: {input_file} -> {output_file}")
    print(f"      versão={version}, payload={payload_size} bytes, rodapé={len(footer)} bytes")


def pack_sys(input_payload: Path, output_file: Path, version: int = 1) -> None:
    payload = input_payload.read_bytes()
    header = HEADER_STRUCT.pack(version, len(payload))
    output_file.write_bytes(header + payload + b"\x00\x00\x00\x00")
    print(f"[OK] Empacotado: {input_payload} -> {output_file}")
    print(f"      versão={version}, payload={len(payload)} bytes, rodapé=4 bytes nulos")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Desempacotador/Empacotador para ftinfo.sys"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_unpack = sub.add_parser("unpack", help="extrai o payload do .sys")
    p_unpack.add_argument("input", type=Path, help="arquivo .sys de entrada")
    p_unpack.add_argument("output", type=Path, help="arquivo de saída (payload)")

    p_pack = sub.add_parser("pack", help="recria o .sys a partir do payload")
    p_pack.add_argument("input", type=Path, help="payload de entrada")
    p_pack.add_argument("output", type=Path, help="arquivo .sys de saída")
    p_pack.add_argument(
        "--version", type=int, default=1, help="versão do cabeçalho (padrão: 1)"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "unpack":
        unpack_sys(args.input, args.output)
    elif args.command == "pack":
        pack_sys(args.input, args.output, version=args.version)


if __name__ == "__main__":
    main()
