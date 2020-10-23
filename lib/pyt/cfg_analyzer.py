"""The comand line module of PyT."""

import os

from lib.logger import LOG
from lib.pyt.analysis.constraint_table import initialize_constraint_table
from lib.pyt.analysis.fixed_point import analyse
from lib.pyt.cfg import make_cfg
from lib.pyt.core.ast_helper import generate_ast
from lib.pyt.core.project_handler import get_directory_modules, get_modules
from lib.pyt.vulnerabilities import find_insights, find_vulnerabilities
from lib.pyt.vulnerabilities.vulnerability_helper import SanitisedVulnerability
from lib.pyt.web_frameworks import FrameworkAdaptor, is_taintable_function

default_blackbox_mapping_file = os.path.join(
    os.path.dirname(__file__), "vulnerability_definitions", "blackbox_mapping.json"
)


default_trigger_word_file = os.path.join(
    os.path.dirname(__file__), "vulnerability_definitions", "all_sources_sinks.pyt"
)


def deep_analysis(src, files):
    has_unsanitised_vulnerabilities = False
    cfg_list = list()
    insights = []
    framework_route_criteria = is_taintable_function
    for path in sorted(files, key=os.path.dirname, reverse=True):
        directory = os.path.dirname(path)
        project_modules = get_modules(directory, prepend_module_root=False)
        local_modules = get_directory_modules(directory)

        LOG.debug(f"Generating AST and CFG for {path}")
        try:
            tree = generate_ast(path)
            if not tree:
                continue
        except Exception as e:
            LOG.debug(e)
        try:
            violations = find_insights(tree, path)
            if violations:
                insights += violations
            cfg = make_cfg(
                tree,
                project_modules,
                local_modules,
                path,
                allow_local_directory_imports=True,
            )
            cfg_list.append(cfg)
        except Exception as e:
            LOG.debug(e)

    try:
        # Taint all possible entry points
        LOG.debug("Determining taints")
        FrameworkAdaptor(
            cfg_list, project_modules, local_modules, framework_route_criteria
        )
        LOG.debug("Building constraints table")
        initialize_constraint_table(cfg_list)
        LOG.debug("About to begin deep analysis")
        analyse(cfg_list)
    except Exception as e:
        LOG.debug(e)
    LOG.debug("Finding vulnerabilities from the graph")
    vulnerabilities = find_vulnerabilities(
        cfg_list, default_blackbox_mapping_file, default_trigger_word_file,
    )
    if vulnerabilities:
        has_unsanitised_vulnerabilities = any(
            not isinstance(v, SanitisedVulnerability) for v in vulnerabilities
        )
    return vulnerabilities, insights, has_unsanitised_vulnerabilities
