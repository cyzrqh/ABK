"""Match SUSFS direct hooks to real providers without duplicating runtime hooks."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/fix_sukisu_susfs.py"

HOOKS = r'''
#ifdef CONFIG_KSU_SUSFS
extern bool ksu_selinux_hide_running __read_mostly;
extern int my_setprocattr(const char *name, void *value, size_t size);
#endif
static int selinux_setprocattr(const char *name, void *value, size_t size)
{
    return 11;
}
#ifdef CONFIG_KSU_SUSFS
static int handle_selinux_setprocattr(const char *name, void *value, size_t size)
{
    if ((likely(!strcmp(name, "current") &&
                current_uid().val >= 10000 &&
                ksu_selinux_hide_running)))
        return my_setprocattr(name, value, size);
    return selinux_setprocattr(name, value, size);
}
#endif
static setprocattr_fn lsm_callback =
#ifdef CONFIG_KSU_SUSFS
    LSM_HOOK_INIT(setprocattr, handle_selinux_setprocattr);
#else
    LSM_HOOK_INIT(setprocattr, selinux_setprocattr);
#endif
'''

SELINUXFS = r'''
#ifdef CONFIG_KSU_SUSFS
extern bool ksu_selinux_hide_running __read_mostly;
extern ssize_t my_write_context(struct file *file, char *buf, size_t size);
extern ssize_t my_write_access(struct file *file, char *buf, size_t size);
#endif
static ssize_t sel_write_context(struct file *file, char *buf, size_t size)
{
    return 12;
}
#ifdef CONFIG_KSU_SUSFS
static ssize_t handle_sel_write_context(struct file *file, char *buf, size_t size) {
    if ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))
        return my_write_context(file, buf, size);
    return sel_write_context(file, buf, size);
}
#endif
static ssize_t sel_write_access(struct file *file, char *buf, size_t size);
#ifdef CONFIG_KSU_SUSFS
static ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size);
#endif
static write_op_fn write_op[] = {
#ifdef CONFIG_KSU_SUSFS
    [SEL_ACCESS] = handle_sel_write_access,
#else
    [SEL_ACCESS] = sel_write_access,
#endif
#ifdef CONFIG_KSU_SUSFS
    [SEL_CONTEXT] = handle_sel_write_context,
#else
    [SEL_CONTEXT] = sel_write_context,
#endif
};
static ssize_t sel_write_access(struct file *file, char *buf, size_t size)
{
    return 13;
}
#ifdef CONFIG_KSU_SUSFS
static ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size)
{
    if ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))
        return my_write_access(file, buf, size);
    return sel_write_access(file, buf, size);
}
#endif
'''

EXEC = r'''
#ifdef CONFIG_KSU_SUSFS
#ifndef KSU_NO_PREINIT
extern int ksu_setup_preinit_file(void);
extern int ksu_preinit_handle_post_execveat(void);
#endif
#endif
static int run_exec_hook(void)
{
#ifdef CONFIG_KSU_SUSFS
#ifndef KSU_NO_PREINIT
    return ksu_setup_preinit_file() + ksu_preinit_handle_post_execveat();
#endif
#endif
    return 0;
}
'''

RUNTIME = r'''
static setprocattr_fn orig_setprocattr;
static write_op_fn orig_context_write, orig_access_write;
static int __nocfi my_setprocattr(const char *name, void *value, size_t size)
{
    if (current_uid().val < 10000)
        return orig_setprocattr(name, value, size);
    return 21;
}
static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    if (current_uid().val < 10000)
        return orig_context_write(file, buf, size);
    return 22;
}
static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (current_uid().val < 10000)
        return orig_access_write(file, buf, size);
    return 23;
}
struct runtime_hook { setprocattr_fn replacement; };
static struct runtime_hook selinux_setprocattr_hook = {my_setprocattr};
static int ksu_lsm_hook(struct runtime_hook *hook)
{
    /* The real hook requires a slot containing the resolved native target. */
    if (lsm_callback != selinux_setprocattr)
        return -1;
    orig_setprocattr = lsm_callback;
    lsm_callback = hook->replacement;
    return 0;
}
static void ksu_patch_text(write_op_fn *slot, write_op_fn *replacement)
{
    *slot = *replacement;
}
static int enable_runtime(void)
{
    if (ksu_lsm_hook(&selinux_setprocattr_hook))
        return -1;
    orig_context_write = write_op[SEL_CONTEXT];
    orig_access_write = write_op[SEL_ACCESS];
    write_op_fn context = my_write_context, access = my_write_access;
    ksu_patch_text(&write_op[SEL_CONTEXT], &context);
    ksu_patch_text(&write_op[SEL_ACCESS], &access);
    ksu_selinux_hide_running = true;
    return 0;
}
'''


class SukiSUSUSFSHookCompatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("fix_sukisu_susfs_hooks", SCRIPT)
        cls.patcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.patcher)

    def fixture(self, directory):
        root = Path(directory)
        ksu = root / "KernelSU/kernel"
        (ksu / "feature").mkdir(parents=True)
        (ksu / "Kbuild").write_text("kernelsu-objs += feature/selinux_hide.o\n", encoding="utf-8")
        (ksu / "feature/selinux_hide.c").write_text(RUNTIME, encoding="utf-8")
        for relative, text in (
            ("security/selinux/hooks.c", HOOKS),
            ("security/selinux/selinuxfs.c", SELINUXFS),
            ("fs/exec.c", EXEC),
        ):
            path = root / "common" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root, ksu

    def patch(self, root, ksu):
        changed = []
        self.patcher.patch_kernel_hook_compat(root, ksu, changed)
        return changed

    def snapshot(self, root):
        return {path.relative_to(root): path.read_bytes() for path in root.rglob("*.c")}

    def test_runtime_owner_restores_native_slots_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            runtime = (ksu / "feature/selinux_hide.c").read_bytes()
            self.assertEqual(len(self.patch(root, ksu)), 3)
            hooks = (root / "common/security/selinux/hooks.c").read_text()
            selinuxfs = (root / "common/security/selinux/selinuxfs.c").read_text()
            self.assertNotIn("my_setprocattr", hooks)
            self.assertNotIn("handle_selinux_setprocattr", hooks)
            self.assertIn("LSM_HOOK_INIT(setprocattr, selinux_setprocattr)", hooks)
            self.assertNotIn("my_write_context", selinuxfs)
            self.assertNotIn("my_write_access", selinuxfs)
            self.assertNotIn("handle_sel_write", selinuxfs)
            self.assertIn("[SEL_CONTEXT] = sel_write_context", selinuxfs)
            self.assertIn("[SEL_ACCESS] = sel_write_access", selinuxfs)
            self.assertIn("extern bool ksu_selinux_hide_running", hooks)
            self.assertEqual((ksu / "feature/selinux_hide.c").read_bytes(), runtime)
            self.assertIn(self.patcher.PREINIT_DISABLE, (root / "common/fs/exec.c").read_text())
            snapshot = self.snapshot(root)
            self.assertEqual(self.patch(root, ksu), [])
            self.assertEqual(self.snapshot(root), snapshot)

    def test_actual_global_definitions_keep_direct_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            provider = "\n".join(f"int {name}(void)\n{{\n    return 0;\n}}" for name in (
                *self.patcher.PREINIT_SYMBOLS, "my_setprocattr", "my_write_context", "my_write_access",
            ))
            (ksu / "providers.c").write_text(provider, encoding="utf-8")
            before = self.snapshot(root)
            self.assertEqual(self.patch(root, ksu), [])
            self.assertEqual(self.snapshot(root), before)

    def test_comments_prototypes_and_static_functions_are_not_global_providers(self):
        source = r'''
/* int symbol(void) { return 0; } */
// int symbol(void) { return 0; }
const char *fake = "int symbol(void) { return 0; }";
extern int symbol(void);
int symbol(void);
static int __nocfi symbol(void)
{
    return 0;
}
'''
        self.assertEqual(self.patcher.function_definitions(source, "symbol"), ["static"])
        self.assertEqual(self.patcher.function_definitions("int __nocfi symbol(\n void\n)\n{ return 1; }", "symbol"), ["global"])

    def test_partial_preinit_provider_stops_before_writing_any_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            (ksu / "preinit.c").write_text("int ksu_setup_preinit_file(void) { return 0; }\n", encoding="utf-8")
            before = self.snapshot(root)
            with self.assertRaisesRegex(SystemExit, "incomplete SUSFS preinit"):
                self.patch(root, ksu)
            self.assertEqual(self.snapshot(root), before)

    def test_unguarded_preinit_call_stops_before_writing_any_source(self):
        for source in (
            "extern int ksu_setup_preinit_file(void);\nint run(void) { return ksu_setup_preinit_file(); }\n",
            EXEC + "\nint outside(void) { return ksu_setup_preinit_file(); }\n",
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root, ksu = self.fixture(directory)
                (root / "common/fs/exec.c").write_text(source, encoding="utf-8")
                before = self.snapshot(root)
                with self.assertRaisesRegex(SystemExit, "missing KSU_NO_PREINIT guards"):
                    self.patch(root, ksu)
                self.assertEqual(self.snapshot(root), before)

    def test_new_backend_removes_only_our_previous_disable(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            self.patch(root, ksu)
            (ksu / "preinit.c").write_text("\n".join(
                f"int {name}(void) {{ return 0; }}" for name in self.patcher.PREINIT_SYMBOLS
            ), encoding="utf-8")
            self.assertEqual(len(self.patch(root, ksu)), 1)
            self.assertEqual((root / "common/fs/exec.c").read_text(), EXEC)

    def test_user_preinit_disable_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            path = root / "common/fs/exec.c"
            source = "#define KSU_NO_PREINIT\n" + EXEC
            path.write_text(source, encoding="utf-8")
            self.patch(root, ksu)
            self.assertEqual(path.read_text(), source)

    def test_unknown_selinux_wrapper_or_missing_runtime_owner_is_rejected(self):
        for broken in ("wrapper", "provider", "callback"):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as directory:
                root, ksu = self.fixture(directory)
                path = root / "common/security/selinux/hooks.c"
                if broken == "wrapper":
                    path.write_text(HOOKS.replace("return my_setprocattr", "audit_change();\n        return my_setprocattr"), encoding="utf-8")
                elif broken == "callback":
                    path.write_text(HOOKS.replace("LSM_HOOK_INIT(setprocattr, handle_selinux_setprocattr)", "OTHER_CALLBACK(handle_selinux_setprocattr)"), encoding="utf-8")
                else:
                    (ksu / "feature/selinux_hide.c").write_text("/* no runtime owner */\n", encoding="utf-8")
                before = self.snapshot(root)
                with self.assertRaises(SystemExit):
                    self.patch(root, ksu)
                self.assertEqual(self.snapshot(root), before)

    @unittest.skipUnless(shutil.which("cc"), "hook behavior checks require a C compiler")
    def test_generated_sources_link_and_runtime_hide_still_owns_callbacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root, ksu = self.fixture(directory)
            self.patch(root, ksu)
            headers = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#define CONFIG_KSU_SUSFS 1
#define __read_mostly
#define __nocfi
#define likely(x) (x)
#define LSM_HOOK_INIT(head, callback) callback
#define SEL_ACCESS 0
#define SEL_CONTEXT 1
struct file { int unused; };
typedef int (*setprocattr_fn)(const char *, void *, size_t);
typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);
struct uid { int val; };
static int uid = 1000;
static struct uid current_uid(void) { return (struct uid){uid}; }
bool ksu_selinux_hide_running;
'''
            source = headers + '\n#include "common/security/selinux/hooks.c"\n#include "common/security/selinux/selinuxfs.c"\n#include "common/fs/exec.c"\n#include "KernelSU/kernel/feature/selinux_hide.c"\n' + r'''
int main(void)
{
    assert(run_exec_hook() == 0);
    assert(lsm_callback == selinux_setprocattr);
    assert(write_op[SEL_CONTEXT] == sel_write_context);
    assert(write_op[SEL_ACCESS] == sel_write_access);
    for (uid = 1000; uid <= 10000; uid += 9000) {
        assert(lsm_callback("current", NULL, 0) == 11);
        assert(write_op[SEL_CONTEXT](NULL, NULL, 0) == 12);
        assert(write_op[SEL_ACCESS](NULL, NULL, 0) == 13);
    }
    assert(enable_runtime() == 0);
    uid = 10000;
    assert(lsm_callback("current", NULL, 0) == 21);
    assert(write_op[SEL_CONTEXT](NULL, NULL, 0) == 22);
    assert(write_op[SEL_ACCESS](NULL, NULL, 0) == 23);
    uid = 1000;
    assert(lsm_callback("current", NULL, 0) == 11);
    assert(write_op[SEL_CONTEXT](NULL, NULL, 0) == 12);
    assert(write_op[SEL_ACCESS](NULL, NULL, 0) == 13);
    return 0;
}
'''
            c_path = root / "hooks.c"
            binary = root / ("hooks.exe" if os.name == "nt" else "hooks")
            c_path.write_text(source, encoding="utf-8")
            compiled = subprocess.run([shutil.which("cc"), "-std=gnu11", "-Werror=implicit-function-declaration", str(c_path), "-o", str(binary)], capture_output=True, encoding="utf-8", errors="replace")
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            try:
                result = subprocess.run([str(binary)], capture_output=True, encoding="utf-8", errors="replace")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                # Windows can briefly retain a handle after the test exits.
                # Match the existing execve fixture's bounded cleanup retry.
                for attempt in range(50):
                    try:
                        binary.unlink(missing_ok=True)
                        break
                    except PermissionError:
                        if os.name != "nt" or attempt == 49:
                            raise
                        time.sleep(0.1)


if __name__ == "__main__":
    unittest.main()
