# save as flip_bit.py
import sys
def flip_bit(path, offset_zero_based, bit_index=0):
    # bit_index: 0 is LSB, 7 is MSB
    with open(path, 'r+b') as f:
        f.seek(offset_zero_based)
        b = f.read(1)
        if not b:
            raise SystemExit("offset out of range")
        val = b[0] ^ (1 << bit_index)
        f.seek(offset_zero_based)
        f.write(bytes([val]))
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("offset", type=int)
    p.add_argument("--bit", type=int, default=0)
    args = p.parse_args()
    flip_bit(args.file, args.offset, args.bit)

