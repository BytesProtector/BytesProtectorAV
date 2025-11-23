import os, json, hashlib, math, pathlib
try:
    import pefile
except: pefile = None
try:
    import elftools.elf.elffile as elffile
except: elffile = None
try:
    import macholib.MachO as macho
except: macho = None

HEUR_F = pathlib.Path(__file__).with_name("heuristics.json")

# ---------- tiny utils ----------
def entropy(data: bytes) -> float:
    if not data: return 0
    s = float(len(data))
    return -sum((c/s) * math.log2(c/s) for c in (data.count(b) for b in range(256)) if c)

def hash8(data: bytes, slide=8):
    """return list of 8-byte rolling hashes (jenkins one-at-a-time)"""
    if len(data) < 8: return []
    hashes = []
    for i in range(len(data) - 7):
        h = 0
        for b in data[i:i+8]:
            h += b
            h &= 0xFFFFFFFF
            h += (h << 10) & 0xFFFFFFFF
            h ^= (h >> 6)
        h += (h << 3) & 0xFFFFFFFF
        h ^= (h >> 11)
        h += (h << 15) & 0xFFFFFFFF
        hashes.append(h & 0xFFFFFFFFFFFFFFFF)
    return hashes

# ---------- rule evaluators ----------
class PEChecker:
    def __init__(self, path):
        self.ok = False
        try:
            self.pe = pefile.PE(path, fast_load=True)
            self.ok = True
        except: pass
    def section(self, name):
        if not self.ok: return None
        for s in self.pe.sections:
            if name.encode() in s.Name:
                return s
        return None
    def rwx_sections(self):
        if not self.ok: return []
        out = []
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_WRITE   = 0x80000000
        for s in self.pe.sections:
            mask = s.Characteristics
            if (mask & IMAGE_SCN_MEM_EXECUTE) and (mask & IMAGE_SCN_MEM_WRITE):
                out.append(s)
        return out
    def imports(self):
        if not self.ok: return set()
        self.pe.parse_data_directories()
        imps = set()
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imps.add(imp.name.decode(errors="ignore"))
        return imps
    def overlay(self):
        if not self.ok: return b""
        largest = max(s.PointerToRawData + s.SizeOfRawData for s in self.pe.sections)
        with open(self.pe_path, "rb") as f:
            f.seek(largest)
            return f.read()
    def entry_point_bytes(self, n=8192):
        if not self.ok: return b""
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        rva = self.pe.get_offset_from_rva(ep)
        with open(self.pe_path, "rb") as f:
            f.seek(rva)
            return f.read(n)

class ELFChecker:
    def __init__(self, path):
        self.ok = False
        try:
            self.elf = elffile.ELFFile(open(path, "rb"))
            self.ok = True
        except: pass
    def is_static(self):
        if not self.ok: return False
        for seg in self.elf.iter_segments():
            if seg.header.p_type == "PT_INTERP":
                return False
        return True
    def is_stripped(self):
        if not self.ok: return False
        return self.elf.header.e_shoff == 0

class MachOChecker:
    def __init__(self, path):
        self.ok = False
        try:
            self.m = macho.MachO(path)
            self.ok = True
        except: pass
    def ad_hoc_signature(self):
        if not self.ok: return False
        for header in self.m.headers:
            for cmd in header.commands:
                if cmd[0].cmd == 0x1db:  # CS_CodeDirectory
                    return True
        return False

# ---------- main engine ----------
class HeuristicEngine:
    def __init__(self, rules_file=HEUR_F):
        with open(rules_file) as f:
            self.rules = json.load(f)["rule_set"]
    def evaluate(self, path: str) -> (bool, int, list):
        """
        returns (detected, score, reasons)
        """
        reasons = []
        score = 0
        detected = False
        blob = pathlib.Path(path).read_bytes()
        ep8 = hash8(blob[:8192])

        for rule in self.rules:
            try:
                if rule["type"] == "structural":
                    ok, add, msg = self._structural(rule, path, blob, ep8)
                elif rule["type"] == "import_combination":
                    ok, add, msg = self._import_combo(rule, path)
                elif rule["type"] == "code_hash":
                    ok, add, msg = self._code_hash(rule, ep8)
                elif rule["type"] == "entropy":
                    ok, add, msg = self._entropy(rule, blob)
                else:
                    continue
                if ok:
                    score += add
                    reasons.append(msg)
            except Exception as e:
                # never crash the engine
                continue
        detected = score >= 6
        return detected, min(score, 10), reasons

    # ---- individual evaluators ----
    def _structural(self, rule, path, blob, ep8):
        os_req = rule.get("os", "windows")
        if os_req == "windows" and pefile is None: return False,0,""
        if os_req == "linux" and elffile is None: return False,0,""
        if os_req == "macos" and macho is None: return False,0,""

        cond = rule["condition"]
        pe = PEChecker(path) if os_req=="windows" else None
        elf = ELFChecker(path) if os_req=="linux" else None
        mach = MachOChecker(path) if os_req=="macos" else None

        # evaluate simple JSON condition
        if cond.startswith("pe."):
            if not pe or not pe.ok: return False,0,""
            # tiny evaluator for the JSON conditions we wrote
            if "rwx_sections" in cond and pe.rwx_sections():
                return True, rule["severity"], rule["name"]
            if "overlay.size" in cond:
                overlay = blob[pe.pe.sections[-1].PointerToRawData+pe.pe.sections[-1].SizeOfRawData:]
                if len(overlay) > 51200 and entropy(overlay) > 7.5:
                    return True, rule["severity"], rule["name"]
            if "import_table.size == 0" in cond and not pe.imports():
                return True, rule["severity"], rule["name"]
        if cond.startswith("elf."):
            if not elf or not elf.ok: return False,0,""
            if "e_shoff == 0" in cond and elf.is_stripped():
                return True, rule["severity"], rule["name"]
        if cond.startswith("macho."):
            if not mach or not mach.ok: return False,0,""
            if "ad-hoc" in cond and mach.ad_hoc_signature():
                return True, rule["severity"], rule["name"]
        return False,0,""

    def _import_combo(self, rule, path):
        pe = PEChecker(path)
        if not pe.ok: return False,0,""
        needed = rule["condition"].split("contains_all(")[1].split(")")[0].strip("[]'\"")
        apis = {a.strip(" '\"") for a in needed.split(",")}
        if apis.issubset(pe.imports()):
            return True, rule["severity"], rule["name"]
        return False,0,""

    def _code_hash(self, rule, ep8):
        want = rule["condition"].split("==")[1].strip().strip("'\"")
        want_int = int(want.replace(" ",""), 16)
        if want_int in ep8:
            return True, rule["severity"], rule["name"]
        return False,0,""

    def _entropy(self, rule, blob):
        return False, 0, ""

# ---------- singleton ----------
_HEUR = HeuristicEngine()

def scan(path: str) -> (bool, int, list):
    """public entry point used by GUI"""
    return _HEUR.evaluate(path)