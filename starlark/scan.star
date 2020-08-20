# vi:syntax=python

load("github.com/mesosphere/dispatch-catalog/starlark/stable/git@0.0.7", "git_checkout_dir")
load("github.com/mesosphere/dispatch-catalog/starlark/stable/pipeline@0.0.7", "storage_resource")

__doc__ = """
# Scan

Provides methods for running [Scan](https://www.shiftleft.io/scan/) on your CI.

To import, add the following to your Dispatchfile:

```
load("github.com/shiftleftsecurity/sast-scan/starlark/scan@master", "sast_scan")
```

For help, please visit https://slscan.io/en/latest/integrations/dispatch/
"""

def sast_scan(task_name, git_name, image="shiftleft/scan:latest", src=None, extra_scan_options=None, **kwargs):
    """
    Runs a SAST Scan using the provided image on a given directory.

    #### Parameters
    - *task_name* : name of the task to be created
    - *git_name* : input git resource name
    - *image* : image (with tag) of the Shiftleft Scan
    - *src* : Optional string to override the `src` directory to run the scan. Defaults to given git resource directory.
    - *extra_scan_options* : Optional array containing flag names (and values) to be passed to scan command
    """
    if not src:
        src = git_checkout_dir(git_name)
    output_name = storage_resource("storage-{}".format(task_name))
    if not extra_scan_options:
        extra_scan_options=[]
    task(task_name, inputs=[git_name], outputs=[output_name], steps=[
        k8s.corev1.Container(
            name="sast-scan-shiftleft-{}".format(git_name),
            image=image,
            command=[
                "scan",
                "--build",
                "--src={}".format(src),
                "--out_dir={}".format("$(resources.outputs.{}.path)".format(output_name)),
            ] + extra_scan_options,
            **kwargs
        )])
    return output_name
