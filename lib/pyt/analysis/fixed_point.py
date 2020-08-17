"""This module implements the fixed point algorithm."""
from lib.pyt.analysis.constraint_table import constraint_table
from lib.pyt.analysis.reaching_definitions_taint import ReachingDefinitionsTaintAnalysis


class FixedPointAnalysis:
    """Run the fix point analysis."""

    def __init__(self, cfg):
        """Fixed point analysis.

        Analysis must be a dataflow analysis containing a 'fixpointmethod'
        method that analyses one CFG."""
        self.analysis = ReachingDefinitionsTaintAnalysis(cfg)
        self.cfg = cfg

    def fixpoint_runner(self):
        """Work list algorithm that runs the fixpoint algorithm."""
        q = self.cfg.nodes

        while q != []:
            if q[0] is None:
                continue
            x_i = constraint_table[q[0]]  # x_i = q[0].old_constraint
            self.analysis.fixpointmethod(q[0])  # y = F_i(x_1, ..., x_n);
            y = constraint_table[q[0]]  # y = q[0].new_constraint

            if y != x_i:
                for node in self.analysis.dep(q[0]):  # for (v in dep(v_i))
                    q.append(node)  # q.append(v):
                constraint_table[
                    q[0]
                ] = y  # q[0].old_constraint = q[0].new_constraint # x_i = y
            q = q[1:]  # q = q.tail()  # The list minus the head


def analyse(cfg_list):
    """Analyse a list of control flow graphs with a given analysis type."""
    for cfg in cfg_list:
        analysis = FixedPointAnalysis(cfg)
        analysis.fixpoint_runner()
