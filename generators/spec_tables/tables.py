"""The CESR code tables for genus `AAA` version 2.00, read out of the pinned specification text.

Three tables are read:

- the Encoding Scheme Table, whose `Format` column gives, per selector, how many characters of a
  code are hard (`*` and `$`), how many are soft size digits (`#`) and how many lead bytes (`%`)
  the raw value carries;
- the Master code table for genus/version `-_AAACAA`, which gives the primitive codes with their
  full lengths and the count codes;
- the Annex indexed code table, which gives each indexed signature code's code, index and ondex
  lengths and its full length.

Where a row cannot be read consistently with the scheme its selector implies, it is recorded in
``Tables.anomalies`` and left out rather than guessed at.
"""

from dataclasses import dataclass, field

from . import spec_source

ENCODING_SCHEME_HEADING = "Encoding Scheme Table"
MASTER_HEADING = (
    "Master code table for genus/version `-_AAACAA` (KERI/ACDC protocol stack Version 2.00)"
)
INDEXED_HEADING = (
    "Indexed code table for genus/version `--AAACAA` (KERI/ACDC protocol stack version 2.00)"
)
GENUS_ROWS = ("-_AAABAA", "-_AAACAA")


@dataclass(frozen=True)
class Scheme:
    hs: int  # hard size in characters: selector and type
    ss: int  # soft size in characters: base 64 size or count digits
    ls: int  # lead bytes prepended to the raw value


@dataclass(frozen=True)
class Primitive:
    code: str
    description: str
    fs: int | None  # full size in characters; None when the raw size is variable
    special: bool  # the row carries a value in its code (tags, labels) rather than a plain raw


@dataclass(frozen=True)
class Indexed:
    code: str
    description: str
    cs: int  # code size: hard part plus index and ondex digits
    ms: int  # index digits
    os: int  # ondex digits
    fs: int


@dataclass
class Tables:
    primitive_schemes: dict[str, Scheme]  # keyed by selector character, or "" for 1-char codes
    count_schemes: dict[str, Scheme]  # keyed by "small", "large", "genus"
    primitives: dict[str, Primitive]
    count_codes: dict[str, str]  # hard code -> description
    indexed: dict[str, Indexed]
    anomalies: list[str] = field(default_factory=list)

    def scheme_for_code(self, code: str) -> Scheme:
        first = code[0]
        key = "" if first.isalpha() else first
        if key not in self.primitive_schemes:
            raise KeyError(f"No primitive code table has the selector {first!r}.")
        return self.primitive_schemes[key]

    def count_scheme(self, code: str) -> Scheme:
        if code.startswith("--"):
            return self.count_schemes["large"]
        if code.startswith("-_"):
            return self.count_schemes["genus"]
        if code.startswith("-") and len(code) > 1 and code[1].isalpha():
            return self.count_schemes["small"]
        raise KeyError(f"No count code table has the selector of {code!r}.")

    def raw_size(self, code: str) -> int:
        prim = self.primitives[code]
        if prim.fs is None:
            raise ValueError(f"The code {code!r} has a variable raw size.")
        scheme = self.scheme_for_code(code)
        return (prim.fs - scheme.hs - scheme.ss) * 3 // 4 - scheme.ls


def _scheme(fmt: str) -> Scheme:
    return Scheme(hs=fmt.count("*") + fmt.count("$"), ss=fmt.count("#"), ls=fmt.count("%"))


def _int(cell: str) -> int | None:
    cell = cell.replace("\\*", "").replace("*", "").strip()
    return int(cell) if cell else None


def load(text: str | None = None) -> "Tables":
    """Read the tables from ``text``, by default the pinned specification."""
    text = spec_source.load_spec() if text is None else text
    anomalies: list[str] = []

    primitive_schemes: dict[str, Scheme] = {}
    count_schemes: dict[str, Scheme] = {}
    for row in spec_source.table_after(text, ENCODING_SCHEME_HEADING):
        if not row[0]:
            continue
        universal, selector, fmt = row[1], row[2], row[8]
        if "TBD" in row[3]:
            continue
        if universal == "-":
            kind = {"[A-Z,a-z]": "small", "-": "large", "_": "genus"}[selector]
            count_schemes[kind] = _scheme(fmt)
        else:
            primitive_schemes["" if universal == "[A-Z,a-z]" else universal] = _scheme(fmt)

    tmp = Tables(primitive_schemes, count_schemes, {}, {}, {}, anomalies)
    in_primitives = False
    for row in spec_source.table_after(text, MASTER_HEADING):
        code, description = row[0], row[1]
        if description == "Primitive Matter Codes":
            in_primitives = True
        if not code or " " in code or code in GENUS_ROWS or code == "_":
            continue
        if code.startswith("-"):
            hard = code.rstrip("#")
            digits = len(code) - len(hard)
            if digits != tmp.count_scheme(hard).ss:
                anomalies.append(
                    f"Master table row {code!r} has {digits} size digits, but its selector "
                    f"implies {tmp.count_scheme(hard).ss}; row left out."
                )
                continue
            tmp.count_codes[hard] = description
        elif in_primitives:
            fs = _int(row[4])
            count_length = _int(row[3])
            special = fs is not None and (count_length is not None or "lead size" in description)
            tmp.primitives[code] = Primitive(code, description, fs, special)

    for row in spec_source.table_after(text, INDEXED_HEADING):
        code = row[0]
        if not code:
            continue
        hard = code.rstrip("#")
        cs, ms, os_, fs = _int(row[2]), _int(row[3]), _int(row[4]), _int(row[5])
        if len(code) != cs or cs != len(hard) + ms + os_:
            anomalies.append(f"Indexed table row {code!r} is inconsistent; row left out.")
            continue
        tmp.indexed[hard] = Indexed(hard, row[1], cs, ms, os_, fs)
    return tmp
