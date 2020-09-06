"""This module implements the fixed point algorithm."""
from lib.pyt.analysis.constraint_table import constraint_table
from lib.pyt.analysis.reaching_definitions_taint import ReachingDefinitionsTaintAnalysis

max_analysis_steps = 20
max_runs = 100
max_none_runs = 3


class FixedPointAnalysis:
    """Run the fix point analysis."""

    def __init__(self, cfg):
        """Fixed point analysis.

        Analysis must be a dataflow analysis containing a 'fixpointmethod'
        method that analyses one CFG."""
        self.analysis = ReachingDefinitionsTaintAnalysis(cfg)
        self.cfg = cfg

    def fixpoint_runner(self, max_analysis_steps, max_runs):
        """Work list algorithm that runs the fixpoint algorithm."""
        q = self.cfg.nodes
        cnt = 0
        none_break_cnt = 0
        while q:
            if q[0] is None:
                if none_break_cnt > max_none_runs:
                    break
                else:
                    none_break_cnt = none_break_cnt + 1
                    continue
            cnt = cnt + 1
            x_i = constraint_table[q[0]]  # x_i = q[0].old_constraint
            self.analysis.fixpointmethod(q[0])  # y = F_i(x_1, ..., x_n);
            y = constraint_table[q[0]]  # y = q[0].new_constraint

            if y != x_i:
                acnt = 0
                for node in self.analysis.dep(q[0]):  # for (v in dep(v_i))
                    q.append(node)  # q.append(v):
                    acnt = acnt + 1
                    if acnt > max_analysis_steps:
                        break
                constraint_table[
                    q[0]
                ] = y  # q[0].old_constraint = q[0].new_constraint # x_i = y
            q = q[1:]  # q = q.tail()  # The list minus the head
            if not q:
                break
            if cnt > max_runs:
                break


def analyse(cfg_list):
    """Analyse a list of control flow graphs with a given analysis type."""
    for cfg in cfg_list:
        analysis = FixedPointAnalysis(cfg)
        analysis.fixpoint_runner(
            max_analysis_steps=max_analysis_steps, max_runs=max_runs
        )
