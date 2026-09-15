import csv
import io
import ipaddress
import pathlib
import re
import urllib.request

FEED = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src" / "core" / "c2list.h"
CAP = 32000

def public_ipv4(text):
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None

def main():
    raw = urllib.request.urlopen(FEED, timeout=60).read().decode("utf-8", "replace")
    found = {}
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 5:
            continue
        date, kind, value, tags = row[0], row[2].lower(), row[3], row[4]
        if "#c2" not in tags.lower().split():
            continue
        if kind == "ip":
            ip = public_ipv4(value.strip())
        elif kind == "url":
            m = re.match(r"^[a-z]+://([0-9.]+)(?::\d+)?(?:/|$)", value.strip(), re.I)
            ip = public_ipv4(m.group(1)) if m else None
        else:
            ip = None
        if ip:
            found[ip] = max(found.get(ip, ""), date)

    ordered = sorted(found, key=lambda ip: found[ip], reverse=True)
    kept, size = [], 0
    for ip in ordered:
        if size + len(ip) + 1 > CAP:
            break
        kept.append(ip)
        size += len(ip) + 1

    lines = ",\"\n    \"".join(",".join(kept[i:i + 8]) for i in range(0, len(kept), 8))
    OUT.write_text(
        "#ifndef WIRECEE_C2LIST_H\n#define WIRECEE_C2LIST_H\n\n"
        f"#define C2_LIST_COUNT {len(kept)}\n"
        f"static const char C2_LIST[] =\n    \"{lines}\";\n\n#endif\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"{len(found)} C2 addresses found, {len(kept)} written to {OUT}")

if __name__ == "__main__":
    main()
