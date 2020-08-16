"""The comand line module of PyT."""

import os
import traceback

from lib.logger import LOG
from lib.pyt.analysis.constraint_table import initialize_constraint_table
from lib.pyt.analysis.fixed_point import analyse
from lib.pyt.cfg import make_cfg
from lib.pyt.core.ast_helper import generate_ast
from lib.pyt.core.project_handler import get_directory_modules, get_modules
from lib.pyt.vulnerabilities import find_vulnerabilities
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
    framework_route_criteria = is_taintable_function
    for path in sorted(files):
        directory = os.path.dirname(path)
        project_modules = get_modules(directory, prepend_module_root=False)
        local_modules = get_directory_modules(directory)
        tree = generate_ast(path)
        if not tree:
            continue
        try:
            cfg = make_cfg(
                tree,
                project_modules,
                local_modules,
                path,
                allow_local_directory_imports=True,
            )
            cfg_list = [cfg]
            FrameworkAdaptor(
                cfg_list, project_modules, local_modules, framework_route_criteria
            )
        except Exception as e:
            LOG.debug(e)
            traceback.print_exc()

    # Add all the route functions to the cfg_list
    try:
        initialize_constraint_table(cfg_list)
        analyse(cfg_list)
    except Exception as e:
        LOG.debug(e)
        traceback.print_exc()
    vulnerabilities = find_vulnerabilities(
        cfg_list, default_blackbox_mapping_file, default_trigger_word_file,
    )
    if vulnerabilities:
        has_unsanitised_vulnerabilities = any(
            not isinstance(v, SanitisedVulnerability) for v in vulnerabilities
        )
    return vulnerabilities, has_unsanitised_vulnerabilities
