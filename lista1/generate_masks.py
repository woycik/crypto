import json
from pathlib import Path


def bits_to_mask(bits: list[int]) -> int:
    mask = 0
    for bit in bits:
        mask |= 1 << (bit - 1)
    return mask


def emit(mask_name: str, mask_value: int) -> None:
    if mask_value:
        print(f"static uint32_t {mask_name} = 0x{mask_value:08x};")


def process_item(name: str, spec: dict[str, list[int]]) -> None:
    masks = {
        "ZERO": bits_to_mask(spec.get("zero", [])),
        "ONE":  bits_to_mask(spec.get("one", [])),
        "COPY": bits_to_mask(spec.get("copy", [])),
        "DIFF": bits_to_mask(spec.get("diff", [])),
    }

    base_name = name.upper()
    for suffix, value in masks.items():
        emit(f"MASK_{base_name}_{suffix}", value)


def main() -> None:
    data_file = Path("data.json")

    with data_file.open("r", encoding="utf-8") as f:
        config = json.load(f)

    for name, spec in config.items():
        process_item(name, spec)


if __name__ == "__main__":
    main()