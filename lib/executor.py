import io
import logging
import os
import subprocess

import reporter.grafeas as grafeas
import reporter.licence as licence

import lib.config as config
import lib.convert as convertLib
import lib.utils as utils
from lib.telemetry import track

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


def exec_tool(args, cwd=None, stdout=subprocess.PIPE):
    """
    Convenience method to invoke cli tools

    Args:
      args cli command and args
    """
    try:
        LOG.info("=" * 80)
        LOG.debug('⚡︎ Executing "{}"'.format(" ".join(args)))
        subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ,
            check=False,
            shell=False,
            encoding="utf-8",
        )
    except Exception as e:
        LOG.exception(e)


def execute_default_cmd(
    cmd_map_list, type_str, tool_name, src, reports_dir, convert,
):
    """
    Method to execute default command for the given type

    Args:
      cmd_map_list Default commands in the form of a dict (multiple) or list
      type_str Project type
      tool_name Tool name
      src Project dir
      reports_dir Directory for output reports
      convert Boolean to enable normalisation of reports json
    """
    # Check if there is a default command specified for the given type
    # Create the reports dir
    os.makedirs(reports_dir, exist_ok=True)
    report_fname_prefix = os.path.join(reports_dir, tool_name + "-report")
    default_cmd = " ".join(cmd_map_list) % dict(
        src=src,
        reports_dir=reports_dir,
        report_fname_prefix=report_fname_prefix,
        type=type_str,
    )
    # Try to detect if the output could be json
    outext = ".out"
    if default_cmd.find("json") > -1:
        outext = ".json"
    if default_cmd.find("csv") > -1:
        outext = ".csv"
    if default_cmd.find("sarif") > -1:
        outext = ".sarif"
    report_fname = report_fname_prefix + outext

    # If the command doesn't support file output then redirect stdout automatically
    stdout = None
    if reports_dir and default_cmd.find(report_fname_prefix) == -1:
        report_fname = report_fname_prefix + outext
        stdout = io.open(report_fname, "w")
        LOG.debug("Output will be written to {}".format(report_fname))

    # If the command is requesting list of files then construct the argument
    filelist_prefix = "(filelist="
    if default_cmd.find(filelist_prefix) > -1:
        si = default_cmd.find(filelist_prefix)
        ei = default_cmd.find(")", si + 10)
        ext = default_cmd[si + 10 : ei]
        filelist = utils.find_files(src, ext)
        delim = " "
        default_cmd = default_cmd.replace(
            filelist_prefix + ext + ")", delim.join(filelist)
        )
    cmd_with_args = default_cmd.split(" ")
    exec_tool(cmd_with_args, cwd=src, stdout=stdout)
    # Should we attempt to convert the report to sarif format
    if (
        convert
        and config.tool_purpose_message.get(cmd_with_args[0])
        and os.path.isfile(report_fname)
    ):
        crep_fname = utils.get_report_file(
            tool_name, reports_dir, convert, ext_name="sarif"
        )
        convertLib.convert_file(
            cmd_with_args[0], cmd_with_args[1:], src, report_fname, crep_fname,
        )
    elif type_str == "depscan":
        # Convert depscan and license scan files to html
        depscan_files = utils.find_files(reports_dir, "depscan", True)
        for df in depscan_files:
            if not df.endswith(".html"):
                depscan_data = grafeas.parse(df)
                if depscan_data and len(depscan_data):
                    html_fname = df.replace(".json", ".html")
                    grafeas.render_html(depscan_data, html_fname)
                    track({"id": config.get("run_uuid"), df: depscan_data})
                    LOG.debug(
                        "Depscan and HTML report written to file: %s, %s 👍",
                        df,
                        html_fname,
                    )
        licence_files = utils.find_files(reports_dir, "license", True)
        for lf in licence_files:
            if not lf.endswith(".html"):
                licence_data = licence.parse(lf)
                if licence_data and len(licence_data):
                    html_fname = lf.replace(".json", ".html")
                    licence.render_html(licence_data, html_fname)
                    track({"id": config.get("run_uuid"), lf: licence_data})
                    LOG.debug(
                        "Licence check and HTML report written to file: %s, %s 👍",
                        lf,
                        html_fname,
                    )
