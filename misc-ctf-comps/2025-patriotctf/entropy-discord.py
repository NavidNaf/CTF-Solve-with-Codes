#!/usr/bin/env python3
# Solve the entropy-discord binary via symbolic execution.

import angr
import claripy
from pathlib import Path


def main() -> None:
    binary_path = Path(__file__).with_name("entropy-discord")
    proj = angr.Project(binary_path, auto_load_libs=False)

    max_len = 32
    sym_bytes = [claripy.BVS(f"b{i}", 8) for i in range(max_len)]
    sym_input = claripy.Concat(*sym_bytes)

    # Constrain to printable ASCII (space through ~).
    state = proj.factory.full_init_state(
        stdin=angr.SimFileStream("stdin", content=sym_input, has_end=True)
    )
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.LAZY_SOLVES)
    for b in sym_bytes:
        state.solver.add(claripy.And(b >= 0x20, b <= 0x7E))

    def is_success(s):
        out = s.posix.dumps(1)
        return b"flag" in out.lower() or b"pctf{" in out or b"}" in out

    fail_markers = [b"fail", b"wrong", b"bad", b"try", b"entropy"]

    def is_fail(s):
        out = s.posix.dumps(1).lower()
        return any(m in out for m in fail_markers)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=is_success, avoid=is_fail, num_find=1, max_steps=1000)

    if not simgr.found:
        return

    found = simgr.found[0]
    solution = found.posix.dumps(0).split(b"\n")[0]
    stdout = found.posix.dumps(1)
    flag = None
    for line in stdout.splitlines():
        if b"{" in line and b"}" in line:
            flag = line.decode(errors="ignore")
            break
    if flag is None:
        flag = solution.decode(errors="ignore")
    print(flag)


if __name__ == "__main__":
    main()
