"""Call graph generation from binaries using Ghidra via pyhidra."""

import json
import logging
import os
from pathlib import Path

import pyhidra

pyhidra.start(True)

from ghidra.util.task import ConsoleTaskMonitor

log = logging.getLogger(__name__)


class CallGraphGenerator:
    """Extracts call graphs from compiled binaries using Ghidra.

    Produces a JSON structure:
        {library: str, edges: [[src_idx, dst_idx], ...], nodes: {idx: {name: str}}}
    """

    def __init__(self, bin_path, project_location, project_name, lib_name):
        self.n2idx = {}
        self.idx2n = {}
        self.nodes = {}
        self.edges = []
        self.lib_name = lib_name
        self.next_index = 0
        self.bin_path = bin_path
        self.project_location = project_location
        self.project_name = project_name
        self.monitor = ConsoleTaskMonitor()

    def _get_and_bump_idx(self):
        ret = self.next_index
        self.next_index += 1
        return ret

    def generate(self):
        """Open the binary, analyze it with Ghidra, and extract the call graph.

        Returns a dict with keys: library, edges, nodes.
        """
        with pyhidra.open_program(
            self.bin_path,
            project_location=self.project_location,
            project_name=self.project_name,
            analyze=False,
        ) as flat_api:
            from ghidra.program.util import GhidraProgramUtilities
            from ghidra.app.script import GhidraScriptUtil

            program = flat_api.getCurrentProgram()

            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                GhidraScriptUtil.acquireBundleHostReference()
                flat_api.analyzeAll(program)
                GhidraProgramUtilities.markProgramAnalyzed(program)
                GhidraScriptUtil.releaseBundleHostReference()

            st = program.getSymbolTable()

            # First pass: build node index
            for f in program.functionManager.getFunctions(True):
                lh = st.getLabelHistory(f.getEntryPoint())
                fullname = lh[0].labelString
                if fullname not in self.n2idx:
                    new_idx = self._get_and_bump_idx()
                    self.n2idx[fullname] = new_idx
                    self.idx2n[new_idx] = fullname
                    self.nodes[new_idx] = {"name": fullname}

            # Second pass: callee edges
            for src in program.functionManager.getFunctions(True):
                lh = st.getLabelHistory(src.getEntryPoint())
                srcname = lh[0].labelString
                for dst in src.getCalledFunctions(self.monitor):
                    lh = st.getLabelHistory(dst.getEntryPoint())
                    dstname = lh[0].labelString
                    edge = [self.n2idx[srcname], self.n2idx[dstname]]
                    if edge not in self.edges:
                        self.edges.append(edge)

            # Third pass: caller edges (may add edges missed by callee analysis)
            for dst in program.functionManager.getFunctions(True):
                lh = st.getLabelHistory(dst.getEntryPoint())
                dstname = lh[0].labelString
                for src in dst.getCallingFunctions(self.monitor):
                    lh = st.getLabelHistory(src.getEntryPoint())
                    srcname = lh[0].labelString
                    edge = [self.n2idx[srcname], self.n2idx[dstname]]
                    if edge not in self.edges:
                        self.edges.append(edge)

            return {
                "library": self.lib_name,
                "edges": self.edges,
                "nodes": self.nodes,
            }
