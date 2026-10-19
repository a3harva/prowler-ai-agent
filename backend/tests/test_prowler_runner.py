"""Proves the launch path does not interpolate caller-supplied text: the
docker command is built as a list, with project_id and target_sa_email each
landing as their own argv element, never folded into a shell string. No
Docker daemon is touched — `build_docker_run_command` is pure."""

import inspect

from app.integrations import prowler_runner
from app.integrations.prowler_runner import build_docker_run_command


def test_project_id_and_sa_land_as_discrete_argv_elements():
    cmd = build_docker_run_command(
        container_name="prowler-scan-1",
        prowler_image="toniblyx/prowler:5.39.0",
        host_output_dir="/abs/reports/1",
        project_id="synthetic-project-id",
        target_sa_email="scanner@synthetic-project.invalid",
        gcloud_adc_path="/var/lib/gcloud/adc.json",
    )

    assert cmd[cmd.index("--project-ids") + 1] == "synthetic-project-id"
    assert (
        cmd[cmd.index("--impersonate-service-account") + 1]
        == "scanner@synthetic-project.invalid"
    )
    # Every element is its own list entry — nothing here is a formatted shell
    # string containing more than one logical token.
    assert all(isinstance(part, str) and " " not in part.strip() for part in cmd if part not in (
        "docker", "run",
    ))


def test_no_adc_mount_when_path_empty():
    cmd = build_docker_run_command(
        container_name="prowler-scan-1",
        prowler_image="toniblyx/prowler:5.39.0",
        host_output_dir="/abs/reports/1",
        project_id="proj",
        target_sa_email="sa@proj.iam.gserviceaccount.com",
        gcloud_adc_path="",
    )
    assert "GOOGLE_APPLICATION_CREDENTIALS=/home/prowler/adc.json" not in cmd
    assert "adc.json" not in " ".join(cmd)


def test_hostile_project_id_stays_a_single_argv_element():
    """A project_id could only reach here from a stored `projects` row (see
    services/scans.py), never from free text — but the command-building
    itself must be safe regardless of what string it is handed."""
    hostile = "proj; rm -rf / #"
    cmd = build_docker_run_command(
        container_name="prowler-scan-1",
        prowler_image="toniblyx/prowler:5.39.0",
        host_output_dir="/abs/reports/1",
        project_id=hostile,
        target_sa_email="sa@proj.iam.gserviceaccount.com",
        gcloud_adc_path="",
    )
    assert cmd[cmd.index("--project-ids") + 1] == hostile
    assert cmd.count(hostile) == 1


def test_run_scan_module_never_shells_out_through_a_shell():
    """subprocess with shell=True would let argv elements be re-parsed as
    shell syntax, defeating the list-based safety above. Assert the module
    source never sets shell=True."""
    source = inspect.getsource(prowler_runner)
    assert "shell=True" not in source
