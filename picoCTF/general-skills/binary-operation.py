# Simple binary calculator for two binary inputs.
# Performs arithmetic and bitwise operations using standard Python semantics.


def read_binary(prompt: str) -> int:
    # Read a binary string from stdin and return its integer value.
    raw = input(prompt).strip()
    if not raw:
        raise ValueError("Input cannot be empty.")
    start = 1 if raw.startswith("-") else 0
    digits = raw[start:]
    if not digits or any(ch not in "01" for ch in digits):
        raise ValueError(f"Invalid binary number: '{raw}'")
    return int(raw, 2)


def format_binary(value: int) -> str:
    # Format an integer as a binary string with optional leading minus.
    if value >= 0:
        return bin(value)[2:]
    return "-" + bin(-value)[2:]


def format_hex(value: int) -> str:
    # Format an integer as a hexadecimal string with 0x prefix.
    prefix = "-" if value < 0 else ""
    return f"{prefix}0x{format(abs(value), 'X')}"


def main() -> None:
    try:
        first = read_binary("Enter the first binary number: ")
        second = read_binary("Enter the second binary number: ")
    except ValueError as exc:
        print(f"❌ {exc}")
        return

    print("\nInputs:")
    print(f"First: {format_binary(first)} (hex {format_hex(first)})")
    print(f"Second: {format_binary(second)} (hex {format_hex(second)})")

    print("\nResults:")
    print(f"{format_binary(first)} + {format_binary(second)} = {format_binary(first + second)} (hex {format_hex(first + second)})")
    print(f"{format_binary(first)} - {format_binary(second)} = {format_binary(first - second)} (hex {format_hex(first - second)})")
    print(f"{format_binary(first)} * {format_binary(second)} = {format_binary(first * second)} (hex {format_hex(first * second)})")
    print(f"{format_binary(first)} & {format_binary(second)} = {format_binary(first & second)} (hex {format_hex(first & second)})")
    print(f"{format_binary(first)} | {format_binary(second)} = {format_binary(first | second)} (hex {format_hex(first | second)})")
    print()
    print("Shift operations:")
    print(f"{format_binary(first)} >> 0 = {format_binary(first >> 0)} (hex {format_hex(first >> 0)})")
    print(f"{format_binary(first)} >> 1 = {format_binary(first >> 1)} (hex {format_hex(first >> 1)})")
    print(f"{format_binary(first)} << 0 = {format_binary(first << 0)} (hex {format_hex(first << 0)})")
    print(f"{format_binary(first)} << 1 = {format_binary(first << 1)} (hex {format_hex(first << 1)})")
    print(f"{format_binary(second)} >> 0 = {format_binary(second >> 0)} (hex {format_hex(second >> 0)})")
    print(f"{format_binary(second)} >> 1 = {format_binary(second >> 1)} (hex {format_hex(second >> 1)})")
    print(f"{format_binary(second)} << 0 = {format_binary(second << 0)} (hex {format_hex(second << 0)})")
    print(f"{format_binary(second)} << 1 = {format_binary(second << 1)} (hex {format_hex(second << 1)})")


if __name__ == "__main__":
    main()
