import re

RAW = r'''
Dim LZeWX(88), OodjR, i

LZeWX(0) = "[B"
LZeWX(1) = "YT"
LZeWX(2) = "e["
LZeWX(3) = "]]"
LZeWX(4) = ";$"
LZeWX(5) = "A1"
LZeWX(6) = "23"
LZeWX(7) = "='"
LZeWX(8) = "Ie"
LZeWX(9) = "X("
LZeWX(10) = "Ne"
LZeWX(11) = "W-"
LZeWX(12) = "OB"
LZeWX(13) = "Je"
LZeWX(14) = "CT"
LZeWX(15) = " N"
LZeWX(16) = "eT"
LZeWX(17) = ".W"
LZeWX(18) = "';"
LZeWX(19) = "$B"
LZeWX(20) = "45"
LZeWX(21) = "6="
LZeWX(22) = "'e"
LZeWX(23) = "BC"
LZeWX(24) = "LI"
LZeWX(25) = "eN"
LZeWX(26) = "T)"
LZeWX(27) = ".D"
LZeWX(28) = "OW"
LZeWX(29) = "NL"
LZeWX(30) = "O'"
LZeWX(31) = ";["
LZeWX(32) = "BY"
LZeWX(33) = "Te"
LZeWX(34) = "[]"
LZeWX(35) = "];"
LZeWX(36) = "$C"
LZeWX(37) = "78"
LZeWX(38) = "9="
LZeWX(39) = "'V"
LZeWX(40) = "AN"
LZeWX(41) = "('"
LZeWX(42) = "'h"
LZeWX(43) = "tt"
LZeWX(44) = "p:"
LZeWX(45) = "//"
LZeWX(46) = "45"
LZeWX(47) = ".1"
LZeWX(48) = "26"
LZeWX(49) = ".2"
LZeWX(50) = "09"
LZeWX(51) = ".4"
LZeWX(52) = ":2"
LZeWX(53) = "22/m"
LZeWX(54) = "dm"
LZeWX(55) = ".j"
LZeWX(56) = "pg"
LZeWX(57) = "''"
LZeWX(58) = ")'"
LZeWX(59) = ".R"
LZeWX(60) = "eP"
LZeWX(61) = "LA"
LZeWX(62) = "Ce"
LZeWX(63) = "('"
LZeWX(64) = "VA"
LZeWX(65) = "N'"
LZeWX(66) = ",'"
LZeWX(67) = "AD"
LZeWX(68) = "ST"
LZeWX(69) = "RI"
LZeWX(70) = "NG"
LZeWX(71) = "')"
LZeWX(72) = ";["
LZeWX(73) = "BY"
LZeWX(74) = "Te"
LZeWX(75) = "[]"
LZeWX(76) = "];"
LZeWX(77) = "Ie"
LZeWX(78) = "X("
LZeWX(79) = "$A"
LZeWX(80) = "12"
LZeWX(81) = "3+"
LZeWX(82) = "$B"
LZeWX(83) = "45"
LZeWX(84) = "6+"
LZeWX(85) = "$C"
LZeWX(86) = "78"
LZeWX(87) = "9)"
'''

def parse_fragments(text: str):
    pattern = re.compile(r'LZeWX\((\d+)\)\s*=\s*"([^"]*)"')
    parts = {}
    for idx, value in pattern.findall(text):
        parts[int(idx)] = value
    return parts

def join_fragments(parts: dict[int, str]) -> str:
    if not parts:
        raise ValueError("No fragments found.")
    missing = [i for i in range(min(parts), max(parts) + 1) if i not in parts]
    if missing:
        raise ValueError(f"Missing fragment indexes: {missing}")
    return "".join(parts[i] for i in range(min(parts), max(parts) + 1))

def simplify_powershell(s: str) -> str:
    # remove junk no-op inserts commonly used for obfuscation
    s = s.replace("[BYTe[]];", "")
    s = s.replace("[BYTe[]]", "")

    # parse variables like:
    # $A123='...';$B456='...';$C789='...';IEX($A123+$B456+$C789)
    var_pattern = re.compile(r"(\$\w+)\s*=\s*'((?:''|[^'])*)'")
    vars_found = {
        name: value.replace("''", "'")
        for name, value in var_pattern.findall(s)
    }

    # find final IEX($A+$B+$C...) concatenation
    iex_match = re.search(r"IeX\((\$[A-Za-z0-9_]+(?:\+\$[A-Za-z0-9_]+)*)\)", s, re.IGNORECASE)
    final_expr = None
    if iex_match:
        names = iex_match.group(1).split("+")
        rebuilt = "".join(vars_found.get(name, name) for name in names)
        final_expr = rebuilt

        # apply simple '.Replace('X','Y')' if present in the rebuilt string
        rep = re.search(r"\.RePLACe\('([^']*)','([^']*)'\)", rebuilt, re.IGNORECASE)
        if rep:
            old, new = rep.groups()
            base = re.sub(r"\.RePLACe\('([^']*)','([^']*)'\)", "", rebuilt, flags=re.IGNORECASE)
            final_expr = base.replace(old, new)

    return s, vars_found, final_expr

def main():
    parts = parse_fragments(RAW)
    combined = join_fragments(parts)
    cleaned, variables, final_expr = simplify_powershell(combined)

    print("=== Combined string ===")
    print(combined)
    print()

    print("=== Cleaned string ===")
    print(cleaned)
    print()

    print("=== Extracted variables ===")
    for k, v in sorted(variables.items()):
        print(f"{k} = {v}")
    print()

    print("=== Reconstructed final payload ===")
    if final_expr:
        print(final_expr)
    else:
        print("Could not fully reconstruct final payload.")

if __name__ == "__main__":
    main()
