"""Keep full-matrix kernels paired with the manager for their selected source."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "kernel-full-feature-matrix.yml"


class MatrixManagerPairingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def event_block(self, event):
        match = re.search(
            rf"(?ms)^  {re.escape(event)}:\n(.*?)(?=^  [a-z_]+:|^jobs:|\Z)",
            self.workflow,
        )
        self.assertIsNotNone(match, f"Missing {event} event")
        return match.group(1)

    def job_block(self, job):
        match = re.search(
            rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:|\Z)",
            self.workflow,
        )
        self.assertIsNotNone(match, f"Missing {job} job")
        return match.group(1)

    def test_manual_dispatch_accepts_optional_custom_source(self):
        self.assertRegex(
            self.event_block("workflow_dispatch"),
            r"(?m)^      custom_ref:\n(?:        description:.*\n)?"
            r"        required: false\n        type: string$",
        )

    def test_reusable_workflow_accepts_optional_custom_source(self):
        self.assertRegex(
            self.event_block("workflow_call"),
            r"(?m)^      custom_ref:\n        required: false\n        type: string$",
        )

    def test_kernel_receives_selected_custom_ref(self):
        self.assertIn(
            "      custom_ref: ${{ inputs.custom_ref || '' }}",
            self.job_block("build-full-feature-matrix"),
        )

    def test_manager_is_delivered_by_existing_reusable_workflow(self):
        manager = self.job_block("get-ksu-manager")
        self.assertIn("    uses: ./.github/workflows/get-manager.yml", manager)
        self.assertIn("    secrets: inherit", manager)
        self.assertIn("    if: inputs.kernelsu_variant != 'None'", manager)
        self.assertNotIn("    strategy:", manager)

    def test_manager_and_kernel_receive_same_source_selection(self):
        kernel = self.job_block("build-full-feature-matrix")
        manager = self.job_block("get-ksu-manager")
        self.assertIn("      ksu_variant: ${{ inputs.kernelsu_variant }}", kernel)
        self.assertIn("      kernelsu_variant: ${{ inputs.kernelsu_variant }}", manager)
        for line in (
            "      ksu_branch: ${{ inputs.kernelsu_branch }}",
            "      custom_ref: ${{ inputs.custom_ref || '' }}",
        ):
            self.assertIn(line, kernel)
            self.assertIn(line, manager)

    def test_release_dependencies_stay_on_existing_matrix_jobs(self):
        release = self.job_block("trigger-full-feature-release")
        self.assertIn(
            "    needs:\n      - prepare-matrix\n      - build-full-feature-matrix\n",
            release,
        )
        self.assertNotIn("      - get-ksu-manager\n", release)


if __name__ == "__main__":
    unittest.main()
