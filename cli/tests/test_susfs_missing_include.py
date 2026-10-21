"""Exercise the real workflow repair for rejected SUSFS include hunks."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/build.yml"
COMPILER = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


class SusfsMissingIncludeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        step = cls.workflow.split("- name: 应用 SUSFS 补丁", 1)[1].split(
            "- name: 确保 SUSFS Kconfig 与核心对象", 1
        )[0]
        helper = step.split("fix_missing_susfs_def() {", 1)[1].split(
            "\n            }", 1
        )[0]
        cls.repair = textwrap.dedent(
            helper.split('python3 - "$file" <<\'PY\'\n', 1)[1].split(
                "\n          PY", 1
            )[0]
        )
        cls.step = step

    def apply_repair(self, path):
        subprocess.run(
            [sys.executable, "-c", self.repair, str(path)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_task_mmu_repair_covers_old_and_new_515_sources(self):
        for sublevel in (78, 94, 149):
            with self.subTest(sublevel=sublevel), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "task_mmu.c"
                source = (
                    "#include <linux/mm.h>\n"
                    + ("#include <linux/overflow.h>\n" if sublevel == 149 else "")
                    + "#ifdef CONFIG_KSU_SUSFS\n"
                    "int redirected(struct inode *inode) {\n"
                    "  return SUSFS_IS_INODE_OPEN_REDIRECT(inode);\n"
                    "}\n"
                    "int mapped(struct inode *inode) {\n"
                    "  return SUSFS_IS_INODE_SUS_MAP(inode);\n"
                    "}\n#endif\n"
                )
                path.write_text(source, encoding="utf-8")
                self.apply_repair(path)
                repaired = path.read_text(encoding="utf-8")
                self.assertEqual(repaired.count("#include <linux/susfs_def.h>"), 1)
                self.assertIn(
                    "#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif",
                    repaired,
                )
                self.assertLess(
                    repaired.index("#include <linux/susfs_def.h>"),
                    repaired.index("SUSFS_IS_INODE_OPEN_REDIRECT("),
                )
                self.apply_repair(path)
                self.assertEqual(path.read_text(encoding="utf-8"), repaired)

    def test_memory_anchors_and_fallback_keep_existing_repair(self):
        for anchor in (
            "#include <linux/zswap.h>\n",
            "#include <linux/sched/sysctl.h>\n",
            "#include <linux/mm_inline.h>\n",
            "#include <linux/mm.h>\n",
            "/* No known include anchor. */\n",
        ):
            with self.subTest(anchor=anchor), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "memory.c"
                path.write_text(
                    anchor + "int mapped(void *inode) { return SUSFS_IS_INODE_SUS_MAP(inode); }\n",
                    encoding="utf-8",
                )
                self.apply_repair(path)
                repaired = path.read_text(encoding="utf-8")
                self.assertEqual(repaired.count("#include <linux/susfs_def.h>"), 1)
                self.assertIn(anchor, repaired)

    def test_existing_header_and_unpatched_sources_are_unchanged(self):
        sources = (
            "#include <linux/mm.h>\nint ordinary(void) { return 0; }\n",
            "#include <linux/mm.h>\n#ifdef CONFIG_KSU_SUSFS\n"
            "#include <linux/susfs_def.h>\n#endif\n"
            "int mapped(void *inode) { return SUSFS_IS_INODE_SUS_MAP(inode); }\n",
            '#include "linux/susfs_def.h"\n'
            "int redirected(void *inode) { return SUSFS_IS_INODE_OPEN_REDIRECT(inode); }\n",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "task_mmu.c"
                path.write_text(source, encoding="utf-8")
                self.apply_repair(path)
                self.assertEqual(path.read_text(encoding="utf-8"), source)

    def test_both_repairs_run_after_all_version_specific_fixups(self):
        tail = self.step.split("# Android 16 - 6.12 修复", 1)[1]
        calls = tail.split("\n            fi", 1)[1]
        self.assertIn("fix_missing_susfs_def ./fs/proc/task_mmu.c", calls)
        self.assertIn("fix_missing_susfs_def ./mm/memory.c", calls)
        self.assertNotIn("sub_in_range", calls)

    @unittest.skipUnless(COMPILER, "requires a C compiler")
    def test_rejected_header_hunk_fails_before_repair_and_compiles_after(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            headers = root / "linux"
            headers.mkdir()
            (headers / "mm.h").write_text(
                "struct inode { unsigned long flags; };\n", encoding="utf-8"
            )
            (headers / "susfs_def.h").write_text(
                "#define SUSFS_IS_INODE_OPEN_REDIRECT(inode) (((inode)->flags & 1) != 0)\n"
                "#define SUSFS_IS_INODE_SUS_MAP(inode) (((inode)->flags & 2) != 0)\n",
                encoding="utf-8",
            )
            source = root / "task_mmu.c"
            source.write_text(
                "#include <linux/mm.h>\n"
                "#ifdef CONFIG_KSU_SUSFS\n"
                "int redirected(struct inode *inode) { return SUSFS_IS_INODE_OPEN_REDIRECT(inode); }\n"
                "int mapped(struct inode *inode) { return SUSFS_IS_INODE_SUS_MAP(inode); }\n"
                "#endif\n",
                encoding="utf-8",
            )
            command = [
                COMPILER, "-std=gnu11", "-Werror=implicit-function-declaration",
                "-fsyntax-only", "-DCONFIG_KSU_SUSFS", "-I", str(root), str(source),
            ]
            broken = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("SUSFS_IS_INODE_OPEN_REDIRECT", broken.stderr)
            self.assertIn("SUSFS_IS_INODE_SUS_MAP", broken.stderr)
            self.apply_repair(source)
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run(
                [part for part in command if part != "-DCONFIG_KSU_SUSFS"],
                check=True, capture_output=True, text=True,
            )


if __name__ == "__main__":
    unittest.main()
