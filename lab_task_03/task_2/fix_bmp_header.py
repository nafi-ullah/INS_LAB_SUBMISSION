import sys
def fix_header(orig, encrypted, out):
    with open(orig, 'rb') as f:
        header = f.read(54)
    with open(encrypted, 'rb') as f:
        data = f.read()
    with open(out, 'wb') as f:
        f.write(header + data[54:])
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("orig")
    p.add_argument("enc")
    p.add_argument("out")
    args = p.parse_args()
    fix_header(args.orig, args.enc, args.out)

