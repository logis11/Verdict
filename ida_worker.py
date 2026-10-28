# ida_worker.py
# ── headless idat 내부에서 실행되는 IDAPython 스크립트 (wine 쪽 파이썬) ──
# 하네스가 env 로 명령을 넘기고( IDA_CMD ), 결과 JSON 을 IDA_OUT 경로에 쓴다.
import json, os
import idaapi, idautils, idc
import ida_auto, ida_funcs, ida_name, ida_pro, ida_nalt, ida_loader


def resolve(target):
    """심볼 이름 또는 '0x...' 주소 문자열을 ea 로."""
    if isinstance(target, int):
        return target
    if isinstance(target, str) and target.lower().startswith("0x"):
        return int(target, 16)
    ea = idc.get_name_ea_simple(target)
    if ea != idaapi.BADADDR:
        return ea
    try:
        return int(target, 16)
    except Exception:
        return None


def get_functions():
    out = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        out.append({
            "name":  idc.get_func_name(ea),
            "start": hex(ea),
            "size":  (f.end_ea - ea) if f else 0,
        })
    return out


def get_strings():
    out = []
    for s in idautils.Strings():
        try:
            out.append({"ea": hex(s.ea), "value": str(s)})
        except Exception:
            pass
    return out


def get_imports():
    out = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ""
        def cb(ea, name, ordinal, _mod=mod):
            if name:
                out.append({"module": _mod, "name": name, "ea": hex(ea)})
            return True
        ida_nalt.enum_import_names(i, cb)
    return out


def decompile_func(target):
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "hexrays decompiler not available"}
    ea = resolve(target)
    if ea is None:
        return {"error": f"cannot resolve '{target}'"}
    try:
        cf = ida_hexrays.decompile(ea)
    except Exception as e:
        return {"error": f"decompile exception: {e!r}"}
    if not cf:
        return {"error": "decompile failed"}
    return {"ea": hex(ea), "name": idc.get_func_name(ea), "code": str(cf)}


def disassemble_func(target):
    ea = resolve(target)
    if ea is None:
        return {"error": f"cannot resolve '{target}'"}
    f = ida_funcs.get_func(ea)
    if not f:
        return {"error": "address is not inside a function"}
    lines, cur = [], f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        lines.append(f"{hex(cur)}: {idc.generate_disasm_line(cur, 0)}")
        cur = idc.next_head(cur, f.end_ea)
    return {"ea": hex(f.start_ea), "name": idc.get_func_name(ea),
            "disasm": "\n".join(lines)}


def xrefs_to(target):
    ea = resolve(target)
    if ea is None:
        return {"error": f"cannot resolve '{target}'"}
    out = [{"frm": hex(x.frm), "func": idc.get_func_name(x.frm)}
           for x in idautils.XrefsTo(ea)]
    return {"ea": hex(ea), "xrefs": out}



def build_index():
    """함수 표 + 호출그래프를 **한 번의 IDA 기동으로** 다 낸다.

    호출부(tools._ida_index)가 이걸 디스크에 캐시하므로, find_funcs/func_at/
    callers/callees/callpath 가 전부 추가 기동 없이 로컬에서 돈다.
    코퍼스(.c) 없이 도는 경로에서 항해 툴이 전멸하던 것을 이걸로 메운다.
    """
    import ida_bytes
    funcs, starts = [], set()
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        funcs.append({"name": idc.get_func_name(ea), "start": hex(ea),
                      "end": hex(f.end_ea if f else ea)})
        starts.add(ea)
    calls = {}
    for ea in starts:
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        out = set()
        cur = f.start_ea
        while cur < f.end_ea and cur != idaapi.BADADDR:
            # 직접 call 만. 간접(레지스터/테이블)은 여기서 안 잡힌다 — 그건 icall.py 의 일이다.
            for x in idautils.CodeRefsFrom(cur, 0):
                if x in starts and x != ea:
                    out.add(x)
            nxt = idc.next_head(cur, f.end_ea)
            if nxt <= cur:
                break
            cur = nxt
        if out:
            calls[hex(ea)] = [hex(v) for v in sorted(out)]
    return {"functions": funcs, "calls": calls,
            "note": "직접 call 만. 간접 호출은 미포함 — 도달 불가로 읽지 마라."}


def main():
    ida_auto.auto_wait()                      # 오토분석 끝까지 대기
    cmd  = json.loads(os.environ.get("IDA_CMD", '{"op":"overview"}'))
    op   = cmd.get("op")
    args = cmd.get("args", {})
    try:
        if op == "overview":
            res = {"functions": get_functions()[:600],
                   "imports":   get_imports(),
                   "strings":   get_strings()[:400]}
        elif op == "index":
            res = build_index()
        elif op == "list_functions":
            res = {"functions": get_functions()}
        elif op == "decompile":
            res = decompile_func(args["target"])
        elif op == "disassemble":
            res = disassemble_func(args["target"])
        elif op == "xrefs_to":
            res = xrefs_to(args["target"])
        elif op == "strings":
            res = {"strings": get_strings()}
        elif op == "imports":
            res = {"imports": get_imports()}
        else:
            res = {"error": f"unknown op '{op}'"}
    except Exception as e:
        res = {"error": repr(e)}

    with open(os.environ["IDA_OUT"], "w") as fp:
        json.dump(res, fp)

    # qexit 은 정상 종료 경로를 건너뛰므로 DB 가 unpacked(.id0/.id1/…) 로 남는다.
    # 명시적으로 .i64 로 packing 해야 다음 호출이 DB 를 재사용한다.
    try:
        idc.save_database(idc.get_idb_path(), ida_loader.DBFL_KILL)
    except Exception:
        pass
    ida_pro.qexit(0)


main()
