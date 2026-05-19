#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path

HEADER_STRUCT = struct.Struct("<II")
FOOTER = b"\x00\x00\x00\x00"


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def decode_text(data: bytes) -> str:
    # Korean antigo / Windows ANSI. Se ficar estranho, teste cp949 ou latin1.
    for enc in ("cp949", "euc_kr", "latin1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("latin1", errors="replace")


def encode_text(text: str) -> bytes:
    # Tente preservar compatibilidade com arquivos coreanos antigos.
    try:
        return text.encode("cp949")
    except UnicodeEncodeError:
        return text.encode("latin1", errors="replace")


def unpack_sys(input_file: Path, output_text: Path, key: int) -> None:
    data = input_file.read_bytes()

    if len(data) < HEADER_STRUCT.size:
        raise ValueError("Arquivo muito pequeno para conter cabeçalho válido.")

    version, payload_size = HEADER_STRUCT.unpack_from(data, 0)

    payload_start = HEADER_STRUCT.size
    payload_end = payload_start + payload_size

    payload = data[payload_start:payload_end]
    footer = data[payload_end:]

    if len(payload) != payload_size:
        raise ValueError("Arquivo truncado: payload menor que o tamanho informado.")

    decrypted = xor_bytes(payload, key)
    text = decode_text(decrypted)

    output_text.write_text(text, encoding="utf-8", newline="")

    meta_file = output_text.with_suffix(output_text.suffix + ".meta")
    meta_file.write_text(
        f"version={version}\nkey=0x{key:02X}\nfooter_hex={footer.hex().upper()}\n",
        encoding="utf-8",
    )

    print(f"[OK] Descriptografado: {input_file} -> {output_text}")
    print(f"     version={version}")
    print(f"     payload={payload_size} bytes")
    print(f"     key=0x{key:02X}")
    print(f"     meta={meta_file}")


def pack_sys(input_text: Path, output_file: Path, version: int, key: int) -> None:
    text = input_text.read_text(encoding="utf-8")
    plain_payload = encode_text(text)
    encrypted_payload = xor_bytes(plain_payload, key)

    header = HEADER_STRUCT.pack(version, len(encrypted_payload))
    output_file.write_bytes(header + encrypted_payload + FOOTER)

    print(f"[OK] Reempacotado: {input_text} -> {output_file}")
    print(f"     version={version}")
    print(f"     payload={len(encrypted_payload)} bytes")
    print(f"     key=0x{key:02X}")
    print(f"     footer=4 bytes nulos")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Unpack/pack ftinfo.sys com XOR."
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_unpack = sub.add_parser("unpack", help="extrai e descriptografa o .sys")
    p_unpack.add_argument("input", type=Path)
    p_unpack.add_argument("output", type=Path)
    p_unpack.add_argument("--key", default="0xFF", help="chave XOR. padrão: 0xFF")

    p_pack = sub.add_parser("pack", help="criptografa e recria o .sys")
    p_pack.add_argument("input", type=Path)
    p_pack.add_argument("output", type=Path)
    p_pack.add_argument("--version", type=int, default=1)
    p_pack.add_argument("--key", default="0xFF", help="chave XOR. padrão: 0xFF")

    return parser


def parse_key(value: str) -> int:
    key = int(value, 0)
    if not 0 <= key <= 255:
        raise ValueError("A chave XOR precisa estar entre 0 e 255.")
    return key


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    key = parse_key(args.key)

    if args.command == "unpack":
        unpack_sys(args.input, args.output, key)

    elif args.command == "pack":
        pack_sys(args.input, args.output, args.version, key)


if __name__ == "__main__":
    main()