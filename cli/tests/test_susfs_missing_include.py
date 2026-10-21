"""Exercise the real workflow repair for rejected SUSFS include hunks."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


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
        namespace_helper = step.split("ensure_susfs_namespace_headers() {", 1)[1].split(
            "\n            }", 1
        )[0]
        cls.namespace_repair = textwrap.dedent(
            namespace_helper.split('python3 - "$file" <<\'PY\'\n', 1)[1].split(
                "\n          PY", 1
            )[0]
        )
        cls.step = step

    def apply_repair(self, path):
        return self.run_repair(self.repair, path)

    def run_repair(self, repair, path):
        result = subprocess.run(
            [sys.executable, "-c", repair, str(path)],
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    @staticmethod
    def namespace_source(anchor="#include <linux/fs_context.h>\n", declarations=""):
        return anchor + '#include "internal.h"\n' + declarations + (
            "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
            "int namespace_case(void) {\n"
            "  return VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT + DEFAULT_KSU_MNT_ID\n"
            "    + DEFAULT_KSU_MNT_GROUP_ID + CL_COPY_MNT_NS\n"
            "    + susfs_is_current_ksu_domain() + susfs_is_current_proc_umounted()\n"
            "    + susfs_is_sdcard_android_data_not_decrypted.enabled;\n"
            "}\n#endif\n"
        )

    def test_namespace_rejected_header_hunk_is_restored_on_all_515_sublevels(self):
        for sublevel, header in ((41, "fs.h"), (94, "fs_context.h"), (194, "shmem_fs.h")):
            with self.subTest(sublevel=sublevel), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "namespace.c"
                path.write_text(self.namespace_source(f"#include <linux/{header}>\n"), encoding="utf-8")
                self.run_repair(self.namespace_repair, path)
                repaired = path.read_text(encoding="utf-8")
                for declaration in (
                    "#include <linux/susfs_def.h>",
                    "extern bool susfs_is_current_ksu_domain(void);",
                    "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;",
                    "#define CL_COPY_MNT_NS BIT(25)",
                ):
                    self.assertEqual(repaired.count(declaration), 1)
                    self.assertLess(repaired.index(declaration), repaired.index("int namespace_case"))
                self.assertIn("#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT", repaired)
                self.run_repair(self.namespace_repair, path)
                self.assertEqual(path.read_text(encoding="utf-8"), repaired)

    def test_namespace_partial_and_complete_headers_preserve_existing_declarations(self):
        include = "#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n"
        domain = "extern bool susfs_is_current_ksu_domain(void);\n"
        key = "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\n"
        flag = "#define CL_COPY_MNT_NS BIT(25)\n"
        for declarations in ("", domain, key + flag, domain + key + flag):
            with self.subTest(declarations=declarations), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "namespace.c"
                guarded = "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n" + declarations + "#endif\n"
                source = self.namespace_source("#include <linux/mnt_idmapping.h>\n" + include, guarded)
                path.write_text(source, encoding="utf-8")
                self.run_repair(self.namespace_repair, path)
                repaired = path.read_text(encoding="utf-8")
                for declaration in ("#include <linux/susfs_def.h>", domain.strip(), key.strip(), flag.strip()):
                    self.assertEqual(repaired.count(declaration), 1)
                if declarations == domain + key + flag:
                    self.assertEqual(repaired, source)

    def test_namespace_without_hooks_or_only_comments_is_unchanged(self):
        for source in (
            '#include "internal.h"\nint ordinary(void) { return 0; }\n',
            "/* DEFAULT_KSU_MNT_ID susfs_is_current_ksu_domain CL_COPY_MNT_NS */\n"
            'const char *note = "susfs_is_current_proc_umounted";\n',
            "#ifndef CL_COPY_MNT_NS\n#define CL_COPY_MNT_NS BIT(25)\n#endif\n",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "namespace.c"
                path.write_text(source, encoding="utf-8")
                self.run_repair(self.namespace_repair, path)
                self.assertEqual(path.read_text(encoding="utf-8"), source)

    def test_namespace_unknown_anchors_and_incompatible_declarations_fail_without_writes(self):
        sources = (
            self.namespace_source("#include <linux/unknown.h>\n"),
            self.namespace_source().replace('#include "internal.h"\n', ""),
            self.namespace_source(declarations="extern int susfs_is_current_ksu_domain(void);\n"),
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "namespace.c"
                path.write_text(source, encoding="utf-8")
                with self.assertRaises(AssertionError):
                    self.run_repair(self.namespace_repair, path)
                self.assertEqual(path.read_text(encoding="utf-8"), source)

    @unittest.skipUnless(COMPILER, "requires a C compiler")
    def test_namespace_full_missing_hunk_fails_before_repair_and_compiles_after(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "linux").mkdir()
            (root / "linux/fs_context.h").write_text(
                "#include <stdbool.h>\n#define BIT(n) (1UL << (n))\n"
                "struct static_key_true { int enabled; };\n", encoding="utf-8"
            )
            (root / "linux/susfs_def.h").write_text(
                "#define VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT BIT(24)\n"
                "#define DEFAULT_KSU_MNT_ID 100000\n"
                "#define DEFAULT_KSU_MNT_GROUP_ID 1000\n"
                "static inline bool susfs_is_current_proc_umounted(void) { return false; }\n",
                encoding="utf-8",
            )
            (root / "internal.h").write_text("/* Kernel local declarations. */\n", encoding="utf-8")
            path = root / "namespace.c"
            path.write_text(self.namespace_source(), encoding="utf-8")
            command = [COMPILER, "-std=gnu11", "-Werror=implicit-function-declaration", "-fsyntax-only",
                       "-DCONFIG_KSU_SUSFS", "-DCONFIG_KSU_SUSFS_SUS_MOUNT", "-I", str(root), str(path)]
            broken = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace")
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("CL_COPY_MNT_NS", broken.stderr)
            self.assertIn("susfs_is_current_ksu_domain", broken.stderr)
            self.run_repair(self.namespace_repair, path)
            subprocess.run(command, check=True, capture_output=True, encoding="utf-8", errors="replace")
            subprocess.run([part for part in command if not part.startswith("-DCONFIG_")],
                           check=True, capture_output=True, encoding="utf-8", errors="replace")

    def test_namespace_repair_runs_outside_sublevel_specific_branches(self):
        tail = self.step.split("# Android 16 - 6.12 修复", 1)[1]
        calls = tail.split("\n            fi", 1)[1]
        self.assertIn("ensure_susfs_namespace_headers", calls)
        self.assertNotIn("sub_in_range", calls)

    def test_repair_uses_utf8_with_an_ascii_parent_console(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "内核源码.c"
            path.write_text(
                "/* 保留源码注释 */\n#include <linux/mm.h>\n"
                "int mapped(void *inode) { return SUSFS_IS_INODE_SUS_MAP(inode); }\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii"}):
                result = self.apply_repair(path)
            self.assertIn("已修复", result.stdout)
            self.assertIn(path.name, result.stdout)
            repaired = path.read_text(encoding="utf-8")
            self.assertIn("保留源码注释", repaired)
            self.assertIn("#include <linux/susfs_def.h>", repaired)

    def test_repair_failure_reports_decoded_child_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "缺失源码.c"
            with self.assertRaises(AssertionError) as failure:
                self.apply_repair(path)
            self.assertIn("FileNotFoundError", str(failure.exception))
            self.assertIn(path.name, str(failure.exception))

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
            broken = subprocess.run(command, capture_output=True, encoding="utf-8", errors="replace")
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("SUSFS_IS_INODE_OPEN_REDIRECT", broken.stderr)
            self.assertIn("SUSFS_IS_INODE_SUS_MAP", broken.stderr)
            self.apply_repair(source)
            subprocess.run(command, check=True, capture_output=True, encoding="utf-8", errors="replace")
            subprocess.run(
                [part for part in command if part != "-DCONFIG_KSU_SUSFS"],
                check=True, capture_output=True, encoding="utf-8", errors="replace",
            )


if __name__ == "__main__":
    unittest.main()
