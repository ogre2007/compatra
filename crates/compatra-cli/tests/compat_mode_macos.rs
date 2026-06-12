//! macOS-only compatibility-mode smoke test.
//!
//! The future host-bridged compatibility layer depends on Darwin host
//! behavior, so CI runs this test on an explicit Intel macOS runner. Other
//! hosts keep the test target present but skip the host-specific check.

#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
const HELLO_FIXTURE: &str = "fixtures/macos/bin/arm64_hello";

#[cfg(target_os = "macos")]
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[cfg(target_os = "macos")]
fn fixture_path() -> PathBuf {
    workspace_root().join(HELLO_FIXTURE)
}

#[cfg(target_os = "macos")]
fn compatra_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_compatra")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            workspace_root()
                .join("target")
                .join("release")
                .join("compatra")
        })
}

#[cfg(target_os = "macos")]
fn generated_fixture_dir() -> PathBuf {
    workspace_root().join("target").join("compatra-fixtures")
}

#[cfg(target_os = "macos")]
fn generated_fixture_dir_arg() -> String {
    let dir = generated_fixture_dir();
    fs::create_dir_all(&dir).expect("failed to create generated fixture directory");
    fs::canonicalize(&dir).unwrap_or(dir).display().to_string()
}

#[cfg(target_os = "macos")]
fn text_excerpt(value: &str, max_chars: usize) -> String {
    let mut out = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

#[cfg(target_os = "macos")]
fn stderr_log_excerpt(stderr: &str, max_lines: usize) -> String {
    let lines = stderr.lines().collect::<Vec<_>>();
    let mut excerpt = lines
        .iter()
        .take(max_lines)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > max_lines {
        excerpt.push_str(&format!(
            "\n... omitted {} stderr lines ...",
            lines.len() - max_lines
        ));
    }
    excerpt
}

#[cfg(target_os = "macos")]
fn compile_arm64_write_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_write_hello.c");
    let binary = out_dir.join("arm64_write_hello");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*printf_fn)(const char *, ...);

int main(void) {
    printf("compat %s path\n", "printf");
    void *self = dlopen(NULL, RTLD_NOW);
    printf_fn dyn_printf = (printf_fn)dlsym(self, "printf");
    if (dyn_printf == 0) {
        return 2;
    }
    dyn_printf("compat %s path\n", "dlsym");
    dlclose(self);
    return write(1, "compat write path\n", sizeof("compat write path\n") - 1) < 0;
}
"#,
    )
    .expect("failed to write generated arm64 C fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_identity_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_identity.c");
    let binary = out_dir.join("arm64_identity");
    fs::write(
        &source,
        r#"#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    int pw_ok = pw && pw->pw_name && pw->pw_dir && pw->pw_shell;
    struct passwd *by_name = pw_ok ? getpwnam(pw->pw_name) : 0;
    int pwnam_ok = by_name && by_name->pw_uid == uid;

    char login[256];
    memset(login, 0, sizeof(login));
    int login_ret = getlogin_r(login, sizeof(login));

    int group_count = getgroups(0, 0);
    gid_t groups[32];
    memset(groups, 0, sizeof(groups));
    int group_limit = group_count > 32 ? 32 : group_count;
    int group_read = group_limit > 0 ? getgroups(group_limit, groups) : group_count;

    int ok = pw_ok && pwnam_ok && login_ret == 0 && login[0] != 0 && group_count >= 0 && group_read >= 0;
    printf(
        "compat identity uid=%u pw=%d name=%s dir=%s shell=%s pwnam=%d login_ret=%d login=%s groups=%d read=%d ok=%d\n",
        (unsigned)uid,
        pw_ok,
        pw_ok ? pw->pw_name : "<null>",
        pw_ok ? pw->pw_dir : "<null>",
        pw_ok ? pw->pw_shell : "<null>",
        pwnam_ok,
        login_ret,
        login,
        group_count,
        group_read,
        ok
    );
    return ok ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 identity fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 identity fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 identity fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_printf_varargs_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_printf_varargs.c");
    let binary = out_dir.join("arm64_printf_varargs");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef int (*printf_fn)(const char *, ...);

static void emit_printf(printf_fn fn, const char *label) {
    fn("compat varargs %s ints=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d str=%s hex=%#x ptr=%p char=%c\n",
       label,
       1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
       "stack-ok",
       0x5a,
       (void *)(uintptr_t)0x1234,
       'Z');
}

int main(void) {
    emit_printf(printf, "static");

    void *self = dlopen(NULL, RTLD_NOW);
    printf_fn dyn_printf = (printf_fn)dlsym(self, "printf");
    if (dyn_printf == 0) {
        return 7;
    }
    emit_printf(dyn_printf, "dlsym");
    dlclose(self);
    return 0;
}
"#,
    )
    .expect("failed to write generated arm64 printf varargs C fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 printf varargs fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 printf varargs fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_lifecycle_glue_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_lifecycle_glue.c");
    let binary = out_dir.join("arm64_lifecycle_glue");
    fs::write(
        &source,
        r#"#include <stdlib.h>
#include <unistd.h>

static void mark(const char *text) {
    const char *p = text;
    size_t len = 0;
    while (p[len] != '\0') {
        len++;
    }
    write(1, text, len);
}

__attribute__((constructor))
static void before_main(void) {
    mark("compat lifecycle ctor\n");
}

static void at_exit_one(void) {
    mark("compat lifecycle atexit\n");
}

__attribute__((destructor))
static void after_main(void) {
    mark("compat lifecycle dtor\n");
}

int main(void) {
    int ret = atexit(at_exit_one);
    if (ret == 0) {
        mark("compat lifecycle main atexit_ret=0\n");
    } else {
        mark("compat lifecycle main atexit_ret=nonzero\n");
    }
    return 0;
}
"#,
    )
    .expect("failed to write generated arm64 lifecycle glue C fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 lifecycle glue fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 lifecycle glue fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_exec_model_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_exec_model.c");
    let binary = out_dir.join("arm64_exec_model");
    fs::write(
        &source,
        r#"#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int stdin_fd = fileno(stdin);
    int stdout_fd = fileno(stdout);
    int stderr_fd = fileno(stderr);
    int stdout_puts = fputs("compat exec stdio stdout\n", stdout);
    int stderr_puts = fputs("compat exec stdio stderr\n", stderr);
    printf("compat exec before stdin_fd=%d stdout_fd=%d stderr_fd=%d stdout_puts=%d stderr_puts=%d\n", stdin_fd, stdout_fd, stderr_fd, stdout_puts, stderr_puts);
    fflush(stdout);
    fflush(stderr);
    execl("/bin/echo", "echo", "compat exec child", (char *)0);
    printf("compat exec after errno=%d\n", errno);
    return 7;
}
"#,
    )
    .expect("failed to write generated arm64 exec model C fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 exec model fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 exec model fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_guest_library_init_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let lib_source = out_dir.join("guest_state_lib.c");
    let main_source = out_dir.join("guest_state_main.c");
    let dylib = out_dir.join("libguest_state.dylib");
    let binary = out_dir.join("arm64_guest_state_main");

    fs::write(
        &lib_source,
        r#"#include <stddef.h>
#include <unistd.h>

static int guest_state = 7;

static void mark(const char *text) {
    size_t len = 0;
    while (text[len] != '\0') {
        len++;
    }
    write(1, text, len);
}

__attribute__((constructor))
static void guest_before_main(void) {
    guest_state = 41;
    mark("compat guestlib ctor\n");
}

__attribute__((destructor))
static void guest_after_main(void) {
    mark("compat guestlib dtor\n");
}

int guest_state_value(void) {
    return guest_state + 1;
}

const char *guest_state_text(void) {
    return guest_state == 41 ? "ready" : "cold";
}
"#,
    )
    .expect("failed to write generated arm64 guest library source");

    fs::write(
        &main_source,
        r#"#include <stdio.h>

int guest_state_value(void);
const char *guest_state_text(void);

int main(void) {
    int value = guest_state_value();
    const char *text = guest_state_text();
    printf("compat guestlib main value=%d text=%s\n", value, text);
    return value == 42 ? 0 : 7;
}
"#,
    )
    .expect("failed to write generated arm64 guest library main source");

    let lib_output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-dynamiclib")
        .arg("-install_name")
        .arg("@rpath/libguest_state.dylib")
        .arg("-fno-builtin")
        .arg("-fno-stack-protector")
        .arg(&lib_source)
        .arg("-o")
        .arg(&dylib)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 guest library");
    assert!(
        lib_output.status.success(),
        "failed to compile generated arm64 guest library with status {:?}\nstdout:\n{}\nstderr:\n{}",
        lib_output.status,
        String::from_utf8_lossy(&lib_output.stdout),
        String::from_utf8_lossy(&lib_output.stderr)
    );

    let main_output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&main_source)
        .arg("-L")
        .arg(&out_dir)
        .arg("-lguest_state")
        .arg("-Wl,-rpath,@loader_path")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 guest library main fixture");
    assert!(
        main_output.status.success(),
        "failed to compile generated arm64 guest library main fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        main_output.status,
        String::from_utf8_lossy(&main_output.stdout),
        String::from_utf8_lossy(&main_output.stderr)
    );

    (binary, dylib)
}

#[cfg(target_os = "macos")]
fn compile_universal_native_preferred_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("universal_native_preferred.c");
    let x86_binary = out_dir.join("universal_native_preferred_x86_64");
    let arm64_binary = out_dir.join("universal_native_preferred_arm64");
    let universal_binary = out_dir.join("universal_native_preferred");
    fs::write(
        &source,
        r#"#include <stdio.h>

int main(void) {
#if defined(__x86_64__)
    puts("compat fat native slice=x86_64");
#elif defined(__aarch64__)
    puts("compat fat native slice=arm64");
#else
    puts("compat fat native slice=unknown");
#endif
    return 0;
}
"#,
    )
    .expect("failed to write generated universal fixture source");

    for (target, output_path) in [
        ("x86_64-apple-macos11", &x86_binary),
        ("arm64-apple-macos11", &arm64_binary),
    ] {
        let output = Command::new("xcrun")
            .arg("clang")
            .arg("-target")
            .arg(target)
            .arg("-mmacosx-version-min=11.0")
            .arg(&source)
            .arg("-o")
            .arg(output_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("failed to launch xcrun clang for generated universal fixture");
        assert!(
            output.status.success(),
            "failed to compile generated universal fixture slice {target} with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new("xcrun")
        .arg("lipo")
        .arg("-create")
        .arg("-output")
        .arg(&universal_binary)
        .arg(&x86_binary)
        .arg(&arm64_binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun lipo for generated universal fixture");
    assert!(
        output.status.success(),
        "failed to create generated universal fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    universal_binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_memory_string_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_memory_string_compat.c");
    let binary = out_dir.join("arm64_memory_string_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef strlcpy
#undef strlcpy
#endif
#ifdef strlcat
#undef strlcat
#endif

void *memmem(const void *, size_t, const void *, size_t);
char *strcasestr(const char *, const char *);
size_t strlcpy(char *, const char *, size_t);
size_t strlcat(char *, const char *, size_t);

typedef void *(*malloc_fn)(size_t);
typedef void *(*calloc_fn)(size_t, size_t);
typedef void *(*realloc_fn)(void *, size_t);
typedef void (*free_fn)(void *);
typedef int (*posix_memalign_fn)(void **, size_t, size_t);
typedef void *(*memcpy_fn)(void *, const void *, size_t);
typedef void *(*memmove_fn)(void *, const void *, size_t);
typedef void *(*memset_fn)(void *, int, size_t);
typedef void (*bzero_fn)(void *, size_t);
typedef int (*memcmp_fn)(const void *, const void *, size_t);
typedef size_t (*strlen_fn)(const char *);
typedef int (*strcmp_fn)(const char *, const char *);
typedef int (*strncmp_fn)(const char *, const char *, size_t);
typedef char *(*strcpy_fn)(char *, const char *);
typedef char *(*strncpy_fn)(char *, const char *, size_t);
typedef char *(*strcat_fn)(char *, const char *);
typedef char *(*strchr_fn)(const char *, int);
typedef char *(*strrchr_fn)(const char *, int);
typedef char *(*strdup_fn)(const char *);
typedef void *(*memchr_fn)(const void *, int, size_t);
typedef void *(*memmem_fn)(const void *, size_t, const void *, size_t);
typedef int (*strcasecmp_fn)(const char *, const char *);
typedef int (*strncasecmp_fn)(const char *, const char *, size_t);
typedef size_t (*strlcpy_fn)(char *, const char *, size_t);
typedef size_t (*strlcat_fn)(char *, const char *, size_t);
typedef char *(*strcasestr_fn)(const char *, const char *);
typedef int (*atoi_fn)(const char *);
typedef long (*strtol_fn)(const char *, char **, int);
typedef unsigned long (*strtoul_fn)(const char *, char **, int);
typedef unsigned long long (*strtoull_fn)(const char *, char **, int);

static int all_zero(const unsigned char *buf, unsigned long len) {
    for (unsigned long i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int text_is(const char *text, const char *expected) {
    while (*text && *expected && *text == *expected) {
        text++;
        expected++;
    }
    return *text == 0 && *expected == 0;
}

static int exercise_memstr(
    const char *label,
    malloc_fn malloc_impl,
    calloc_fn calloc_impl,
    realloc_fn realloc_impl,
    free_fn free_impl,
    posix_memalign_fn posix_memalign_impl,
    memcpy_fn memcpy_impl,
    memmove_fn memmove_impl,
    memset_fn memset_impl,
    bzero_fn bzero_impl,
    memcmp_fn memcmp_impl,
    strlen_fn strlen_impl,
    strcmp_fn strcmp_impl,
    strncmp_fn strncmp_impl,
    strcpy_fn strcpy_impl,
    strncpy_fn strncpy_impl,
    strcat_fn strcat_impl,
    strchr_fn strchr_impl,
    strrchr_fn strrchr_impl,
    strdup_fn strdup_impl
) {
    char dst[64];
    memset_impl(dst, '?', sizeof(dst));
    memcpy_impl(dst, "alpha", 6);

    char overlap[16];
    strcpy_impl(overlap, "abcdef");
    memmove_impl(overlap + 2, overlap, 4);
    overlap[6] = 0;

    char copy[80];
    strcpy_impl(copy, "left");
    strcat_impl(copy, "-right");
    strncpy_impl(copy + 11, "pad", 5);

    char *hit = strchr_impl(copy, '-');
    char *last = strrchr_impl(copy, 't');
    char *dup = strdup_impl(copy);

    char *heap = (char *)malloc_impl(16);
    if (heap) {
        strcpy_impl(heap, "heap");
        heap = (char *)realloc_impl(heap, 32);
        if (heap) {
            strcat_impl(heap, "-ok");
        }
    }
    unsigned char *zero = (unsigned char *)calloc_impl(4, 4);
    int zero_ok = zero ? all_zero(zero, 16) : 0;

    void *aligned = 0;
    int pa = posix_memalign_impl(&aligned, 32, 24);
    if (aligned) {
        memset_impl(aligned, 'A', 24);
    }
    unsigned char wiped[8];
    memset_impl(wiped, 0xCC, sizeof(wiped));
    bzero_impl(wiped + 1, 6);
    int bzero_ok = wiped[0] == 0xCC && all_zero(wiped + 1, 6) && wiped[7] == 0xCC;

    int memcmp_eq = memcmp_impl(dst, "alpha", 5);
    unsigned long len = (unsigned long)strlen_impl(dst);
    int cmp_eq = strcmp_impl(dst, "alpha");
    int cmp_lt = strcmp_impl("alpha", "beta");
    int ncmp = strncmp_impl(dst, "alphabet", 5);
    long hit_off = hit ? (long)(hit - copy) : -1;
    long last_off = last ? (long)(last - copy) : -1;
    int ok = text_is(dst, "alpha")
        && text_is(overlap, "ababcd")
        && text_is(copy, "left-right")
        && dup
        && text_is(dup, "left-right")
        && heap
        && text_is(heap, "heap-ok")
        && zero_ok
        && pa == 0
        && aligned
        && (((uintptr_t)aligned) % 32) == 0
        && bzero_ok
        && memcmp_eq == 0
        && len == 5
        && cmp_eq == 0
        && cmp_lt < 0
        && ncmp == 0
        && hit_off == 4
        && last_off == 9;

    printf(
        "compat memstr %s dst=%s overlap=%s copy=%s dup=%s heap=%s zero_ok=%d bzero_ok=%d pa=%d aligned_mod=%lu memcmp=%d len=%lu cmp=%d cmp_lt=%d ncmp=%d hit=%ld last=%ld ok=%d\n",
        label,
        dst,
        overlap,
        copy,
        dup ? dup : "<null>",
        heap ? heap : "<null>",
        zero_ok,
        bzero_ok,
        pa,
        aligned ? (unsigned long)(((uintptr_t)aligned) % 32) : 999UL,
        memcmp_eq,
        len,
        cmp_eq,
        cmp_lt,
        ncmp,
        hit_off,
        last_off,
        ok
    );

    if (dup) {
        free_impl(dup);
    }
    if (heap) {
        free_impl(heap);
    }
    if (zero) {
        free_impl(zero);
    }
    if (aligned) {
        free_impl(aligned);
    }
    return ok ? 0 : 1;
}

static int exercise_memstr_extra(
    const char *label,
    memchr_fn memchr_impl,
    memmem_fn memmem_impl,
    strcasecmp_fn strcasecmp_impl,
    strncasecmp_fn strncasecmp_impl,
    strlcpy_fn strlcpy_impl,
    strlcat_fn strlcat_impl,
    strcasestr_fn strcasestr_impl,
    atoi_fn atoi_impl,
    strtol_fn strtol_impl,
    strtoul_fn strtoul_impl,
    strtoull_fn strtoull_impl
) {
    char mem_buf[] = "alpha-beta-alpha";
    char needle[] = "beta";
    char *memchr_hit = (char *)memchr_impl(mem_buf, '-', sizeof(mem_buf));
    char *memmem_hit = (char *)memmem_impl(mem_buf, sizeof(mem_buf) - 1, needle, 4);
    char *memmem_empty = (char *)memmem_impl(mem_buf, sizeof(mem_buf) - 1, "", 0);
    const char *case_text = "LaunchAgent/Chrome";
    char *case_hit = strcasestr_impl(case_text, "agent");
    int scase = strcasecmp_impl("Hello", "hello");
    int sncase = strncasecmp_impl("LaunchAgent", "launchpad", 6);

    char small[8];
    size_t lcpy = strlcpy_impl(small, "wallet-db", sizeof(small));
    char cat[12];
    strcpy(cat, "key");
    size_t lcat = strlcat_impl(cat, "chain", sizeof(cat));
    char shortcat[6];
    strcpy(shortcat, "ab");
    size_t lcat_trunc = strlcat_impl(shortcat, "cdef", sizeof(shortcat));

    const char *strtol_text = " -0x2a tail";
    char *end = 0;
    long parsed = strtol_impl(strtol_text, &end, 0);
    long end_off = end ? (long)(end - strtol_text) : -1;
    const char *strtoul_text = "0755x";
    end = 0;
    unsigned long uparsed = strtoul_impl(strtoul_text, &end, 0);
    long uend_off = end ? (long)(end - strtoul_text) : -1;
    const char *strtoull_text = "18446744073709551615!";
    end = 0;
    unsigned long long ull = strtoull_impl(strtoull_text, &end, 10);
    long ull_end_off = end ? (long)(end - strtoull_text) : -1;
    int atoi_val = atoi_impl("1234x");

    long memchr_off = memchr_hit ? (long)(memchr_hit - mem_buf) : -1;
    long memmem_off = memmem_hit ? (long)(memmem_hit - mem_buf) : -1;
    long memempty_off = memmem_empty ? (long)(memmem_empty - mem_buf) : -1;
    long case_off = case_hit ? (long)(case_hit - case_text) : -1;
    int ok = memchr_off == 5
        && memmem_off == 6
        && memempty_off == 0
        && case_off == 6
        && scase == 0
        && sncase == 0
        && lcpy == 9
        && text_is(small, "wallet-")
        && lcat == 8
        && text_is(cat, "keychain")
        && lcat_trunc == 6
        && text_is(shortcat, "abcde")
        && parsed == -42
        && end_off == 6
        && uparsed == 493
        && uend_off == 4
        && ull == 18446744073709551615ULL
        && ull_end_off == 20
        && atoi_val == 1234;

    printf(
        "compat memstr-extra %s memchr=%ld memmem=%ld memempty=%ld case=%ld scase=%d sncase=%d lcpy=%lu small=%s lcat=%lu cat=%s trunc=%lu short=%s strtol=%ld end=%ld strtoul=%lu uend=%ld strtoull=%llu ullend=%ld atoi=%d ok=%d\n",
        label,
        memchr_off,
        memmem_off,
        memempty_off,
        case_off,
        scase,
        sncase,
        (unsigned long)lcpy,
        small,
        (unsigned long)lcat,
        cat,
        (unsigned long)lcat_trunc,
        shortcat,
        parsed,
        end_off,
        uparsed,
        uend_off,
        ull,
        ull_end_off,
        atoi_val,
        ok
    );
    return ok ? 0 : 1;
}

int main(void) {
    int failures = 0;
    failures += exercise_memstr(
        "static",
        malloc,
        calloc,
        realloc,
        free,
        posix_memalign,
        memcpy,
        memmove,
        memset,
        bzero,
        memcmp,
        strlen,
        strcmp,
        strncmp,
        strcpy,
        strncpy,
        strcat,
        strchr,
        strrchr,
        strdup
    );
    failures += exercise_memstr_extra(
        "static",
        memchr,
        memmem,
        strcasecmp,
        strncasecmp,
        strlcpy,
        strlcat,
        strcasestr,
        atoi,
        strtol,
        strtoul,
        strtoull
    );

    void *self = dlopen(NULL, RTLD_NOW);
    malloc_fn dyn_malloc = (malloc_fn)dlsym(self, "malloc");
    calloc_fn dyn_calloc = (calloc_fn)dlsym(self, "calloc");
    realloc_fn dyn_realloc = (realloc_fn)dlsym(self, "realloc");
    free_fn dyn_free = (free_fn)dlsym(self, "free");
    posix_memalign_fn dyn_posix_memalign = (posix_memalign_fn)dlsym(self, "posix_memalign");
    memcpy_fn dyn_memcpy = (memcpy_fn)dlsym(self, "memcpy");
    memmove_fn dyn_memmove = (memmove_fn)dlsym(self, "memmove");
    memset_fn dyn_memset = (memset_fn)dlsym(self, "memset");
    bzero_fn dyn_bzero = (bzero_fn)dlsym(self, "bzero");
    memcmp_fn dyn_memcmp = (memcmp_fn)dlsym(self, "memcmp");
    strlen_fn dyn_strlen = (strlen_fn)dlsym(self, "strlen");
    strcmp_fn dyn_strcmp = (strcmp_fn)dlsym(self, "strcmp");
    strncmp_fn dyn_strncmp = (strncmp_fn)dlsym(self, "strncmp");
    strcpy_fn dyn_strcpy = (strcpy_fn)dlsym(self, "strcpy");
    strncpy_fn dyn_strncpy = (strncpy_fn)dlsym(self, "strncpy");
    strcat_fn dyn_strcat = (strcat_fn)dlsym(self, "strcat");
    strchr_fn dyn_strchr = (strchr_fn)dlsym(self, "strchr");
    strrchr_fn dyn_strrchr = (strrchr_fn)dlsym(self, "strrchr");
    strcasestr_fn dyn_strcasestr = (strcasestr_fn)dlsym(self, "strcasestr");
    strdup_fn dyn_strdup = (strdup_fn)dlsym(self, "strdup");
    memchr_fn dyn_memchr = (memchr_fn)dlsym(self, "memchr");
    memmem_fn dyn_memmem = (memmem_fn)dlsym(self, "memmem");
    strcasecmp_fn dyn_strcasecmp = (strcasecmp_fn)dlsym(self, "strcasecmp");
    strncasecmp_fn dyn_strncasecmp = (strncasecmp_fn)dlsym(self, "strncasecmp");
    strlcpy_fn dyn_strlcpy = (strlcpy_fn)dlsym(self, "strlcpy");
    strlcat_fn dyn_strlcat = (strlcat_fn)dlsym(self, "strlcat");
    atoi_fn dyn_atoi = (atoi_fn)dlsym(self, "atoi");
    strtol_fn dyn_strtol = (strtol_fn)dlsym(self, "strtol");
    strtoul_fn dyn_strtoul = (strtoul_fn)dlsym(self, "strtoul");
    strtoull_fn dyn_strtoull = (strtoull_fn)dlsym(self, "strtoull");
    printf(
        "compat memstr dlsym ptrs malloc=%p free=%p memcpy=%p bzero=%p strcmp=%p strcpy=%p strchr=%p strdup=%p posix_memalign=%p\n",
        (void *)dyn_malloc,
        (void *)dyn_free,
        (void *)dyn_memcpy,
        (void *)dyn_bzero,
        (void *)dyn_strcmp,
        (void *)dyn_strcpy,
        (void *)dyn_strchr,
        (void *)dyn_strdup,
        (void *)dyn_posix_memalign
    );
    printf(
        "compat memstr-extra dlsym ptrs memchr=%p memmem=%p strcasecmp=%p strncasecmp=%p strlcpy=%p strlcat=%p strcasestr=%p atoi=%p strtol=%p strtoul=%p strtoull=%p\n",
        (void *)dyn_memchr,
        (void *)dyn_memmem,
        (void *)dyn_strcasecmp,
        (void *)dyn_strncasecmp,
        (void *)dyn_strlcpy,
        (void *)dyn_strlcat,
        (void *)dyn_strcasestr,
        (void *)dyn_atoi,
        (void *)dyn_strtol,
        (void *)dyn_strtoul,
        (void *)dyn_strtoull
    );
    if (!dyn_malloc || !dyn_calloc || !dyn_realloc || !dyn_free || !dyn_posix_memalign || !dyn_memcpy || !dyn_memmove || !dyn_memset || !dyn_bzero || !dyn_memcmp || !dyn_strlen || !dyn_strcmp || !dyn_strncmp || !dyn_strcpy || !dyn_strncpy || !dyn_strcat || !dyn_strchr || !dyn_strrchr || !dyn_strcasestr || !dyn_strdup || !dyn_memchr || !dyn_memmem || !dyn_strcasecmp || !dyn_strncasecmp || !dyn_strlcpy || !dyn_strlcat || !dyn_atoi || !dyn_strtol || !dyn_strtoul || !dyn_strtoull) {
        return 2;
    }
    failures += exercise_memstr(
        "dlsym",
        dyn_malloc,
        dyn_calloc,
        dyn_realloc,
        dyn_free,
        dyn_posix_memalign,
        dyn_memcpy,
        dyn_memmove,
        dyn_memset,
        dyn_bzero,
        dyn_memcmp,
        dyn_strlen,
        dyn_strcmp,
        dyn_strncmp,
        dyn_strcpy,
        dyn_strncpy,
        dyn_strcat,
        dyn_strchr,
        dyn_strrchr,
        dyn_strdup
    );
    failures += exercise_memstr_extra(
        "dlsym",
        dyn_memchr,
        dyn_memmem,
        dyn_strcasecmp,
        dyn_strncasecmp,
        dyn_strlcpy,
        dyn_strlcat,
        dyn_strcasestr,
        dyn_atoi,
        dyn_strtol,
        dyn_strtoul,
        dyn_strtoull
    );
    dlclose(self);
    return failures == 0 ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 memory/string fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 memory/string fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 memory/string fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_startup_glue_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_startup_glue_compat.c");
    let binary = out_dir.join("arm64_startup_glue_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern size_t compat_libcpp_next_prime(size_t) __asm("__ZNSt3__112__next_primeEm");
extern int compat_cxa_guard_acquire(uint64_t *) __asm("___cxa_guard_acquire");
extern void compat_cxa_guard_release(uint64_t *) __asm("___cxa_guard_release");
extern void compat_cxa_guard_abort(uint64_t *) __asm("___cxa_guard_abort");
extern void compat_string_init(void *, const char *, size_t) __asm("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm");
extern void *compat_string_append_cstr_len(void *, const char *, size_t) __asm("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm");
extern void compat_string_push_back(void *, int) __asm("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc");
extern size_t compat_string_find_char(const void *, int, size_t) __asm("__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm");
extern int compat_string_compare(const void *, size_t, size_t, const char *) __asm("__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc");

typedef int (*mlock_fn)(const void *, size_t);
typedef int (*munlock_fn)(const void *, size_t);
typedef int (*madvise_fn)(void *, size_t, int);
typedef int (*pthread_sigmask_fn)(int, const sigset_t *, sigset_t *);
typedef int (*pthread_threadid_np_fn)(pthread_t, uint64_t *);
typedef int (*issetugid_fn)(void);
typedef int (*execl_fn)(const char *, const char *, ...);
typedef int (*system_fn)(const char *);
typedef size_t (*next_prime_fn)(size_t);
typedef int (*cxa_guard_acquire_fn)(uint64_t *);
typedef void (*cxa_guard_void_fn)(uint64_t *);
typedef void (*string_init_fn)(void *, const char *, size_t);
typedef void *(*string_append_cstr_len_fn)(void *, const char *, size_t);
typedef void (*string_push_back_fn)(void *, int);
typedef size_t (*string_find_char_fn)(const void *, int, size_t);
typedef int (*string_compare_fn)(const void *, size_t, size_t, const char *);
typedef size_t (*string_size_fn)(const void *);
typedef int (*string_empty_fn)(const void *);
typedef const char *(*string_data_fn)(const void *);
typedef void (*string_void_fn)(void *);
typedef void (*string_reserve_fn)(void *, size_t);
typedef void (*string_resize_fill_fn)(void *, size_t, int);
typedef void *(*string_assign_string_fn)(void *, const void *);
typedef size_t (*vector_size_fn)(const void *);
typedef int (*vector_empty_fn)(const void *);
typedef const char *(*vector_data_fn)(const void *);
typedef const char *(*vector_index_fn)(const void *, size_t);
typedef void (*vector_void_fn)(void *);
typedef void (*vector_copy_fn)(void *, const void *);
typedef void (*vector_reserve_fn)(void *, size_t);
typedef void (*vector_resize_fill_fn)(void *, size_t, const char *);
typedef void (*vector_push_back_fn)(void *, const char *);

#define COMPAT_STRING_OBJECT_SIZE 24
#define COMPAT_VECTOR_OBJECT_SIZE 24
#define COMPAT_ALT_LONG_FLAG (1ULL << 63)

static unsigned int byte_sum(const unsigned char *buf, size_t len) {
    unsigned int sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += buf[i];
    }
    return sum;
}

static uint64_t load_u64(const unsigned char *ptr) {
    uint64_t value = 0;
    memcpy(&value, ptr, sizeof(value));
    return value;
}

static size_t compat_string_len(const unsigned char *obj) {
    uint64_t word2 = load_u64(obj + 16);
    if ((word2 & COMPAT_ALT_LONG_FLAG) != 0) {
        return (size_t)load_u64(obj + 8);
    }
    return (size_t)(obj[23] & 0x7f);
}

static const char *compat_string_object_data(const unsigned char *obj) {
    uint64_t word2 = load_u64(obj + 16);
    if ((word2 & COMPAT_ALT_LONG_FLAG) != 0) {
        return (const char *)(uintptr_t)load_u64(obj);
    }
    return (const char *)obj;
}

static int exercise_startup_glue(
    const char *label,
    mlock_fn mlock_impl,
    munlock_fn munlock_impl,
    madvise_fn madvise_impl,
    pthread_sigmask_fn pthread_sigmask_impl,
    pthread_threadid_np_fn pthread_threadid_np_impl,
    issetugid_fn issetugid_impl,
    execl_fn execl_impl,
    system_fn system_impl,
    next_prime_fn next_prime_impl,
    cxa_guard_acquire_fn cxa_guard_acquire_impl,
    cxa_guard_void_fn cxa_guard_release_impl,
    cxa_guard_void_fn cxa_guard_abort_impl,
    string_init_fn string_init_impl,
    string_append_cstr_len_fn string_append_cstr_len_impl,
    string_push_back_fn string_push_back_impl,
    string_find_char_fn string_find_char_impl,
    string_compare_fn string_compare_impl,
    string_size_fn string_size_impl,
    string_size_fn string_length_impl,
    string_empty_fn string_empty_impl,
    string_data_fn string_c_str_impl,
    string_data_fn string_data_impl,
    string_size_fn string_capacity_impl,
    string_void_fn string_clear_impl,
    string_reserve_fn string_reserve_impl,
    string_reserve_fn string_resize_impl,
    string_resize_fill_fn string_resize_fill_impl,
    string_void_fn string_default_ctor_impl,
    string_assign_string_fn string_assign_string_impl,
    string_void_fn string_dtor_impl,
    vector_size_fn vector_size_impl,
    vector_size_fn vector_capacity_impl,
    vector_empty_fn vector_empty_impl,
    vector_data_fn vector_data_impl,
    vector_void_fn vector_clear_impl,
    vector_reserve_fn vector_reserve_impl,
    vector_resize_fill_fn vector_resize_fill_impl,
    vector_data_fn vector_begin_impl,
    vector_data_fn vector_end_impl,
    vector_index_fn vector_index_impl,
    vector_data_fn vector_front_impl,
    vector_data_fn vector_back_impl,
    vector_push_back_fn vector_push_back_impl,
    vector_void_fn vector_pop_back_impl,
    vector_void_fn vector_default_ctor_impl,
    vector_copy_fn vector_copy_impl,
    vector_copy_fn vector_assign_impl,
    vector_void_fn vector_dtor_impl
) {
    static unsigned char page[4096] __attribute__((aligned(4096)));
    memset(page, 0x41, sizeof(page));

    int mlock_ret = mlock_impl(page, 64);
    int munlock_ret = munlock_impl(page, 64);
    int madvise_ret = madvise_impl(page, 64, 0);

    sigset_t oldmask;
    memset(&oldmask, 0xA5, sizeof(oldmask));
    int mask_ret = pthread_sigmask_impl(SIG_SETMASK, 0, &oldmask);
    unsigned int oldmask_sum = byte_sum((const unsigned char *)&oldmask, sizeof(oldmask));

    uint64_t thread_id = 0;
    int threadid_ret = pthread_threadid_np_impl(0, &thread_id);

    int ugid = issetugid_impl();

    errno = 0;
    int exec_ret = execl_impl("/compatra/compat/no-such-helper", "no-such-helper", (char *)0);
    int exec_errno = errno;

    int system_ret = system_impl("exit 0");

    size_t prime = next_prime_impl(1000);
    uint64_t guard = 0;
    int guard_first = cxa_guard_acquire_impl(&guard);
    cxa_guard_release_impl(&guard);
    int guard_second = cxa_guard_acquire_impl(&guard);

    uint64_t guard_abort = 0;
    int guard_abort_first = cxa_guard_acquire_impl(&guard_abort);
    cxa_guard_abort_impl(&guard_abort);
    int guard_abort_second = cxa_guard_acquire_impl(&guard_abort);

    unsigned char compat_string[COMPAT_STRING_OBJECT_SIZE];
    memset(compat_string, 0, sizeof(compat_string));
    string_init_impl(compat_string, "glue", 4);
    string_append_cstr_len_impl(compat_string, "-cxx", 4);
    string_push_back_impl(compat_string, '!');
    size_t str_len = compat_string_len(compat_string);
    const char *str_text = compat_string_object_data(compat_string);
    size_t str_find = string_find_char_impl(compat_string, '-', 0);
    int str_compare = string_compare_impl(compat_string, 5, 3, "cxx");
    int str_accessor_proxy = string_size_impl
        && string_length_impl
        && string_empty_impl
        && string_c_str_impl
        && string_data_impl;
    size_t str_size = str_accessor_proxy ? string_size_impl(compat_string) : 0;
    size_t str_length = str_accessor_proxy ? string_length_impl(compat_string) : 0;
    int str_empty = str_accessor_proxy ? string_empty_impl(compat_string) : -1;
    const char *str_cstr = str_accessor_proxy ? string_c_str_impl(compat_string) : 0;
    const char *str_data = str_accessor_proxy ? string_data_impl(compat_string) : 0;
    int str_cstr_ok = str_accessor_proxy && str_cstr && memcmp(str_cstr, "glue-cxx!", 9) == 0;
    int str_data_ok = str_accessor_proxy && str_data && memcmp(str_data, "glue-cxx!", 9) == 0;
    char str_preview[32];
    memset(str_preview, 0, sizeof(str_preview));
    size_t str_preview_len = str_text && str_len < sizeof(str_preview) ? str_len : sizeof(str_preview) - 1;
    if (str_text && str_preview_len > 0) {
        memcpy(str_preview, str_text, str_preview_len);
    }
    int str_base_ok = str_text
        && str_len == 9
        && memcmp(str_preview, "glue-cxx!", 9) == 0
        && str_find == 4
        && str_compare == 0
        && (!str_accessor_proxy
            || (str_size == 9
                && str_length == 9
                && str_empty == 0
                && str_cstr_ok
                && str_data_ok));
    int str_mutator_proxy = str_accessor_proxy
        && string_capacity_impl
        && string_clear_impl
        && string_reserve_impl
        && string_resize_impl
        && string_resize_fill_impl;
    size_t str_capacity = str_mutator_proxy ? string_capacity_impl(compat_string) : 0;
    size_t str_reserve_capacity = 0;
    int str_reserve_ok = 0;
    int str_resize_ok = 0;
    int str_shrink_ok = 0;
    int str_clear_ok = 0;
    int str_lifecycle_proxy = string_default_ctor_impl
        && string_assign_string_impl
        && string_dtor_impl;
    int str_lifecycle_ok = 0;
    if (str_lifecycle_proxy) {
        unsigned char compat_string_assigned[COMPAT_STRING_OBJECT_SIZE];
        memset(compat_string_assigned, 0xCC, sizeof(compat_string_assigned));
        string_default_ctor_impl(compat_string_assigned);
        string_assign_string_impl(compat_string_assigned, compat_string);
        size_t assigned_len = compat_string_len(compat_string_assigned);
        const char *assigned_text = compat_string_object_data(compat_string_assigned);
        str_lifecycle_ok = assigned_len == 9
            && assigned_text
            && memcmp(assigned_text, "glue-cxx!", 9) == 0;
        string_dtor_impl(compat_string_assigned);
    }
    if (str_mutator_proxy) {
        string_reserve_impl(compat_string, 40);
        str_reserve_capacity = string_capacity_impl(compat_string);
        str_reserve_ok = str_reserve_capacity >= 40;

        string_resize_fill_impl(compat_string, 12, '?');
        size_t resized_len = compat_string_len(compat_string);
        const char *resized_text = compat_string_object_data(compat_string);
        str_resize_ok = resized_len == 12
            && resized_text
            && memcmp(resized_text, "glue-cxx!???", 12) == 0;

        string_resize_impl(compat_string, 4);
        size_t shrunk_len = compat_string_len(compat_string);
        const char *shrunk_text = compat_string_object_data(compat_string);
        str_shrink_ok = shrunk_len == 4
            && shrunk_text
            && memcmp(shrunk_text, "glue", 4) == 0
            && string_capacity_impl(compat_string) >= 40;

        string_clear_impl(compat_string);
        str_clear_ok = compat_string_len(compat_string) == 0
            && string_empty_impl(compat_string) == 1
            && string_capacity_impl(compat_string) >= 40;
    }
    int str_ok = str_base_ok
        && (!str_lifecycle_proxy || str_lifecycle_ok)
        && (!str_mutator_proxy
            || (str_capacity == 22
                && str_reserve_ok
                && str_resize_ok
                && str_shrink_ok
                && str_clear_ok));

    unsigned char compat_vector[COMPAT_VECTOR_OBJECT_SIZE];
    memset(compat_vector, 0, sizeof(compat_vector));
    int vec_proxy = vector_size_impl
        && vector_capacity_impl
        && vector_empty_impl
        && vector_data_impl
        && vector_clear_impl
        && vector_reserve_impl
        && vector_resize_fill_impl;
    size_t vec_initial_empty = vec_proxy ? (size_t)vector_empty_impl(compat_vector) : 0;
    size_t vec_size = 0;
    size_t vec_capacity = 0;
    int vec_data_ok = 0;
    int vec_access_proxy = 0;
    int vec_access_ok = 0;
    size_t vec_pushed_size = 0;
    size_t vec_popped_size = 0;
    int vec_lifecycle_proxy = 0;
    int vec_lifecycle_ok = 0;
    int vec_clear_ok = 0;
    if (vec_proxy) {
        const char vec_fill = 'V';
        const char vec_push = '!';
        vector_reserve_impl(compat_vector, 8);
        vector_resize_fill_impl(compat_vector, 6, &vec_fill);
        vec_size = vector_size_impl(compat_vector);
        vec_capacity = vector_capacity_impl(compat_vector);
        const char *vec_data = vector_data_impl(compat_vector);
        vec_data_ok = vec_initial_empty == 1
            && vec_size == 6
            && vec_capacity >= 8
            && vec_data
            && memcmp(vec_data, "VVVVVV", 6) == 0;
        vec_access_proxy = vector_begin_impl
            && vector_end_impl
            && vector_index_impl
            && vector_front_impl
            && vector_back_impl
            && vector_push_back_impl
            && vector_pop_back_impl;
        if (vec_access_proxy) {
            const char *vec_begin = vector_begin_impl(compat_vector);
            const char *vec_end = vector_end_impl(compat_vector);
            const char *vec_index = vector_index_impl(compat_vector, 2);
            const char *vec_front = vector_front_impl(compat_vector);
            const char *vec_back = vector_back_impl(compat_vector);
            vector_push_back_impl(compat_vector, &vec_push);
            vec_pushed_size = vector_size_impl(compat_vector);
            const char *vec_pushed_data = vector_data_impl(compat_vector);
            int vec_push_ok = vec_pushed_size == 7
                && vec_pushed_data
                && memcmp(vec_pushed_data, "VVVVVV!", 7) == 0;
            vector_pop_back_impl(compat_vector);
            vec_popped_size = vector_size_impl(compat_vector);
            const char *vec_popped_data = vector_data_impl(compat_vector);
            vec_access_ok = vec_data
                && vec_begin == vec_data
                && vec_end == vec_data + 6
                && vec_index == vec_data + 2
                && vec_front == vec_data
                && vec_back == vec_data + 5
                && vec_front
                && vec_back
                && *vec_front == 'V'
                && *vec_back == 'V'
                && vec_index
                && *vec_index == 'V'
                && vec_push_ok
                && vec_popped_size == 6
                && vec_popped_data
                && memcmp(vec_popped_data, "VVVVVV", 6) == 0;
        }
        vec_lifecycle_proxy = vector_default_ctor_impl
            && vector_copy_impl
            && vector_assign_impl
            && vector_dtor_impl;
        if (vec_lifecycle_proxy) {
            unsigned char compat_vector_copy[COMPAT_VECTOR_OBJECT_SIZE];
            unsigned char compat_vector_assigned[COMPAT_VECTOR_OBJECT_SIZE];
            memset(compat_vector_copy, 0xCC, sizeof(compat_vector_copy));
            memset(compat_vector_assigned, 0xCC, sizeof(compat_vector_assigned));
            vector_copy_impl(compat_vector_copy, compat_vector);
            vector_default_ctor_impl(compat_vector_assigned);
            vector_assign_impl(compat_vector_assigned, compat_vector_copy);
            const char *copy_data = vector_data_impl(compat_vector_copy);
            const char *assigned_data = vector_data_impl(compat_vector_assigned);
            vec_lifecycle_ok = vector_size_impl(compat_vector_copy) == 6
                && vector_size_impl(compat_vector_assigned) == 6
                && copy_data
                && assigned_data
                && memcmp(copy_data, "VVVVVV", 6) == 0
                && memcmp(assigned_data, "VVVVVV", 6) == 0;
            vector_dtor_impl(compat_vector_copy);
            vector_dtor_impl(compat_vector_assigned);
        }
        vector_clear_impl(compat_vector);
        vec_clear_ok = vector_empty_impl(compat_vector) == 1
            && vector_size_impl(compat_vector) == 0
            && vector_capacity_impl(compat_vector) >= 8;
    }
    int vec_ok = !vec_proxy || (vec_data_ok && (!vec_access_proxy || vec_access_ok) && (!vec_lifecycle_proxy || vec_lifecycle_ok) && vec_clear_ok);

    int ok = mlock_ret == 0
        && munlock_ret == 0
        && madvise_ret == 0
        && mask_ret == 0
        && oldmask_sum == 0
        && threadid_ret == 0
        && thread_id != 0
        && ugid == 0
        && exec_ret == -1
        && exec_errno != 0
        && system_ret == 0
        && prime == 1009
        && guard_first == 1
        && guard_second == 0
        && (guard & 1) == 1
        && guard_abort_first == 1
        && guard_abort_second == 1
        && (guard_abort & 1) == 0
        && str_ok
        && vec_ok;

    printf(
        "compat startup glue %s mlock=%d munlock=%d madvise=%d mask=%d oldmask_size=%lu oldmask_sum=%u threadid=%d thread_id=%llu issetugid=%d execl=%d execl_errno=%d system=%d next_prime=%lu guard_first=%d guard_second=%d guard=0x%llx guard_abort_first=%d guard_abort_second=%d guard_abort=0x%llx str_len=%lu str_accessor_proxy=%d str_size=%lu str_length=%lu str_empty=%d str_text=%.*s str_find=%lu str_compare=%d cstr_ok=%d data_ok=%d str_lifecycle_proxy=%d str_lifecycle_ok=%d str_mutator_proxy=%d str_capacity=%lu reserve_capacity=%lu reserve_ge_40=%d resize_ok=%d shrink_ok=%d clear_ok=%d str_ok=%d vec_proxy=%d vec_size=%lu vec_capacity=%lu vec_data_ok=%d vec_access_proxy=%d vec_access_ok=%d vec_pushed_size=%lu vec_popped_size=%lu vec_lifecycle_proxy=%d vec_lifecycle_ok=%d vec_clear_ok=%d vec_ok=%d ok=%d\n",
        label,
        mlock_ret,
        munlock_ret,
        madvise_ret,
        mask_ret,
        (unsigned long)sizeof(oldmask),
        oldmask_sum,
        threadid_ret,
        (unsigned long long)thread_id,
        ugid,
        exec_ret,
        exec_errno,
        system_ret,
        (unsigned long)prime,
        guard_first,
        guard_second,
        (unsigned long long)guard,
        guard_abort_first,
        guard_abort_second,
        (unsigned long long)guard_abort,
        (unsigned long)str_len,
        str_accessor_proxy,
        (unsigned long)str_size,
        (unsigned long)str_length,
        str_empty,
        (int)str_preview_len,
        str_preview,
        (unsigned long)str_find,
        str_compare,
        str_cstr_ok,
        str_data_ok,
        str_lifecycle_proxy,
        str_lifecycle_ok,
        str_mutator_proxy,
        (unsigned long)str_capacity,
        (unsigned long)str_reserve_capacity,
        str_reserve_ok,
        str_resize_ok,
        str_shrink_ok,
        str_clear_ok,
        str_ok,
        vec_proxy,
        (unsigned long)vec_size,
        (unsigned long)vec_capacity,
        vec_data_ok,
        vec_access_proxy,
        vec_access_ok,
        (unsigned long)vec_pushed_size,
        (unsigned long)vec_popped_size,
        vec_lifecycle_proxy,
        vec_lifecycle_ok,
        vec_clear_ok,
        vec_ok,
        ok
    );
    return ok ? 0 : 1;
}

int main(void) {
    int failures = 0;
    failures += exercise_startup_glue(
        "static",
        mlock,
        munlock,
        madvise,
        pthread_sigmask,
        pthread_threadid_np,
        issetugid,
        execl,
        system,
        compat_libcpp_next_prime,
        compat_cxa_guard_acquire,
        compat_cxa_guard_release,
        compat_cxa_guard_abort,
        compat_string_init,
        compat_string_append_cstr_len,
        compat_string_push_back,
        compat_string_find_char,
        compat_string_compare,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    );

    void *self = dlopen(NULL, RTLD_NOW);
    void *libcxx = dlopen("/usr/lib/libc++.1.dylib", RTLD_NOW);
    void *next_prime_handle = libcxx ? libcxx : self;
    void *string_handle = libcxx ? libcxx : self;
    mlock_fn dyn_mlock = (mlock_fn)dlsym(self, "mlock");
    munlock_fn dyn_munlock = (munlock_fn)dlsym(self, "munlock");
    madvise_fn dyn_madvise = (madvise_fn)dlsym(self, "madvise");
    pthread_sigmask_fn dyn_pthread_sigmask = (pthread_sigmask_fn)dlsym(self, "pthread_sigmask");
    pthread_threadid_np_fn dyn_pthread_threadid_np = (pthread_threadid_np_fn)dlsym(self, "pthread_threadid_np");
    issetugid_fn dyn_issetugid = (issetugid_fn)dlsym(self, "issetugid");
    execl_fn dyn_execl = (execl_fn)dlsym(self, "execl");
    system_fn dyn_system = (system_fn)dlsym(self, "system");
    next_prime_fn dyn_next_prime = (next_prime_fn)dlsym(next_prime_handle, "_ZNSt3__112__next_primeEm");
    cxa_guard_acquire_fn dyn_cxa_guard_acquire = (cxa_guard_acquire_fn)dlsym(self, "__cxa_guard_acquire");
    cxa_guard_void_fn dyn_cxa_guard_release = (cxa_guard_void_fn)dlsym(self, "__cxa_guard_release");
    cxa_guard_void_fn dyn_cxa_guard_abort = (cxa_guard_void_fn)dlsym(self, "__cxa_guard_abort");
    string_init_fn dyn_string_init = (string_init_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm");
    string_append_cstr_len_fn dyn_string_append_cstr_len = (string_append_cstr_len_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm");
    string_push_back_fn dyn_string_push_back = (string_push_back_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc");
    string_find_char_fn dyn_string_find_char = (string_find_char_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm");
    string_compare_fn dyn_string_compare = (string_compare_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKc");
    string_size_fn dyn_string_size = (string_size_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv");
    string_size_fn dyn_string_length = (string_size_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6lengthEv");
    string_empty_fn dyn_string_empty = (string_empty_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5emptyEv");
    string_data_fn dyn_string_c_str = (string_data_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv");
    string_data_fn dyn_string_data = (string_data_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataEv");
    string_size_fn dyn_string_capacity = (string_size_fn)dlsym(string_handle, "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE8capacityEv");
    string_void_fn dyn_string_clear = (string_void_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5clearEv");
    string_reserve_fn dyn_string_reserve = (string_reserve_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEm");
    string_reserve_fn dyn_string_resize = (string_reserve_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEm");
    string_resize_fill_fn dyn_string_resize_fill = (string_resize_fill_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc");
    string_void_fn dyn_string_default_ctor = (string_void_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev");
    string_assign_string_fn dyn_string_assign_string = (string_assign_string_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_");
    string_void_fn dyn_string_dtor = (string_void_fn)dlsym(string_handle, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev");
    vector_size_fn dyn_vector_size = (vector_size_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE4sizeEv");
    vector_size_fn dyn_vector_capacity = (vector_size_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE8capacityEv");
    vector_empty_fn dyn_vector_empty = (vector_empty_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE5emptyEv");
    vector_data_fn dyn_vector_data = (vector_data_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE4dataEv");
    vector_void_fn dyn_vector_clear = (vector_void_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEE5clearEv");
    vector_reserve_fn dyn_vector_reserve = (vector_reserve_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEE7reserveEm");
    vector_resize_fill_fn dyn_vector_resize_fill = (vector_resize_fill_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEE6resizeEmRKc");
    vector_data_fn dyn_vector_begin = (vector_data_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE5beginEv");
    vector_data_fn dyn_vector_end = (vector_data_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE3endEv");
    vector_index_fn dyn_vector_index = (vector_index_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEEixEm");
    vector_data_fn dyn_vector_front = (vector_data_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE5frontEv");
    vector_data_fn dyn_vector_back = (vector_data_fn)dlsym(string_handle, "_ZNKSt3__16vectorIcNS_9allocatorIcEEE4backEv");
    vector_push_back_fn dyn_vector_push_back = (vector_push_back_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEE9push_backERKc");
    vector_void_fn dyn_vector_pop_back = (vector_void_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEE8pop_backEv");
    vector_void_fn dyn_vector_default_ctor = (vector_void_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEEC1Ev");
    vector_copy_fn dyn_vector_copy = (vector_copy_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEEC1ERKS3_");
    vector_copy_fn dyn_vector_assign = (vector_copy_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEEaSERKS3_");
    vector_void_fn dyn_vector_dtor = (vector_void_fn)dlsym(string_handle, "_ZNSt3__16vectorIcNS_9allocatorIcEEED1Ev");

    printf(
        "compat startup glue dlsym ptrs mlock=%p munlock=%p madvise=%p pthread_sigmask=%p pthread_threadid_np=%p issetugid=%p execl=%p system=%p next_prime=%p cxa_guard_acquire=%p cxa_guard_release=%p cxa_guard_abort=%p string_init=%p string_append=%p string_push=%p string_find=%p string_compare=%p string_size=%p string_length=%p string_empty=%p string_cstr=%p string_data=%p string_capacity=%p string_clear=%p string_reserve=%p string_resize=%p string_resize_fill=%p string_ctor=%p string_assign=%p string_dtor=%p vector_size=%p vector_capacity=%p vector_empty=%p vector_data=%p vector_clear=%p vector_reserve=%p vector_resize_fill=%p vector_begin=%p vector_end=%p vector_index=%p vector_front=%p vector_back=%p vector_push=%p vector_pop=%p vector_ctor=%p vector_copy=%p vector_assign=%p vector_dtor=%p\n",
        (void *)dyn_mlock,
        (void *)dyn_munlock,
        (void *)dyn_madvise,
        (void *)dyn_pthread_sigmask,
        (void *)dyn_pthread_threadid_np,
        (void *)dyn_issetugid,
        (void *)dyn_execl,
        (void *)dyn_system,
        (void *)dyn_next_prime,
        (void *)dyn_cxa_guard_acquire,
        (void *)dyn_cxa_guard_release,
        (void *)dyn_cxa_guard_abort,
        (void *)dyn_string_init,
        (void *)dyn_string_append_cstr_len,
        (void *)dyn_string_push_back,
        (void *)dyn_string_find_char,
        (void *)dyn_string_compare,
        (void *)dyn_string_size,
        (void *)dyn_string_length,
        (void *)dyn_string_empty,
        (void *)dyn_string_c_str,
        (void *)dyn_string_data,
        (void *)dyn_string_capacity,
        (void *)dyn_string_clear,
        (void *)dyn_string_reserve,
        (void *)dyn_string_resize,
        (void *)dyn_string_resize_fill,
        (void *)dyn_string_default_ctor,
        (void *)dyn_string_assign_string,
        (void *)dyn_string_dtor,
        (void *)dyn_vector_size,
        (void *)dyn_vector_capacity,
        (void *)dyn_vector_empty,
        (void *)dyn_vector_data,
        (void *)dyn_vector_clear,
        (void *)dyn_vector_reserve,
        (void *)dyn_vector_resize_fill,
        (void *)dyn_vector_begin,
        (void *)dyn_vector_end,
        (void *)dyn_vector_index,
        (void *)dyn_vector_front,
        (void *)dyn_vector_back,
        (void *)dyn_vector_push_back,
        (void *)dyn_vector_pop_back,
        (void *)dyn_vector_default_ctor,
        (void *)dyn_vector_copy,
        (void *)dyn_vector_assign,
        (void *)dyn_vector_dtor
    );

    if (!dyn_mlock || !dyn_munlock || !dyn_madvise || !dyn_pthread_sigmask || !dyn_pthread_threadid_np || !dyn_issetugid || !dyn_execl || !dyn_system || !dyn_next_prime || !dyn_cxa_guard_acquire || !dyn_cxa_guard_release || !dyn_cxa_guard_abort || !dyn_string_init || !dyn_string_append_cstr_len || !dyn_string_push_back || !dyn_string_find_char || !dyn_string_compare || !dyn_string_size || !dyn_string_length || !dyn_string_empty || !dyn_string_c_str || !dyn_string_data || !dyn_string_capacity || !dyn_string_clear || !dyn_string_reserve || !dyn_string_resize || !dyn_string_resize_fill || !dyn_string_default_ctor || !dyn_string_assign_string || !dyn_string_dtor || !dyn_vector_size || !dyn_vector_capacity || !dyn_vector_empty || !dyn_vector_data || !dyn_vector_clear || !dyn_vector_reserve || !dyn_vector_resize_fill || !dyn_vector_begin || !dyn_vector_end || !dyn_vector_index || !dyn_vector_front || !dyn_vector_back || !dyn_vector_push_back || !dyn_vector_pop_back || !dyn_vector_default_ctor || !dyn_vector_copy || !dyn_vector_assign || !dyn_vector_dtor) {
        return 2;
    }
    failures += exercise_startup_glue(
        "dlsym",
        dyn_mlock,
        dyn_munlock,
        dyn_madvise,
        dyn_pthread_sigmask,
        dyn_pthread_threadid_np,
        dyn_issetugid,
        dyn_execl,
        dyn_system,
        dyn_next_prime,
        dyn_cxa_guard_acquire,
        dyn_cxa_guard_release,
        dyn_cxa_guard_abort,
        dyn_string_init,
        dyn_string_append_cstr_len,
        dyn_string_push_back,
        dyn_string_find_char,
        dyn_string_compare,
        dyn_string_size,
        dyn_string_length,
        dyn_string_empty,
        dyn_string_c_str,
        dyn_string_data,
        dyn_string_capacity,
        dyn_string_clear,
        dyn_string_reserve,
        dyn_string_resize,
        dyn_string_resize_fill,
        dyn_string_default_ctor,
        dyn_string_assign_string,
        dyn_string_dtor,
        dyn_vector_size,
        dyn_vector_capacity,
        dyn_vector_empty,
        dyn_vector_data,
        dyn_vector_clear,
        dyn_vector_reserve,
        dyn_vector_resize_fill,
        dyn_vector_begin,
        dyn_vector_end,
        dyn_vector_index,
        dyn_vector_front,
        dyn_vector_back,
        dyn_vector_push_back,
        dyn_vector_pop_back,
        dyn_vector_default_ctor,
        dyn_vector_copy,
        dyn_vector_assign,
        dyn_vector_dtor
    );
    return failures == 0 ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 startup glue fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-lc++")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 startup glue fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 startup glue fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_network_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_network_compat.c");
    let binary = out_dir.join("arm64_network_compat");
    fs::write(
        &source,
        r#"#include <arpa/inet.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <unistd.h>

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef int (*getnameinfo_fn)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
typedef int (*getifaddrs_fn)(struct ifaddrs **);
typedef void (*freeifaddrs_fn)(struct ifaddrs *);
typedef unsigned int (*if_nametoindex_fn)(const char *);
typedef in_addr_t (*inet_addr_fn)(const char *);
typedef int (*inet_aton_fn)(const char *, struct in_addr *);
typedef const char *(*inet_ntop_fn)(int, const void *, char *, socklen_t);
typedef uint32_t (*htonl_fn)(uint32_t);
typedef uint16_t (*htons_fn)(uint16_t);
typedef uint32_t (*ntohl_fn)(uint32_t);
typedef uint16_t (*ntohs_fn)(uint16_t);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef SCNetworkReachabilityRef (*sc_reach_create_fn)(CFAllocatorRef, const char *);
typedef Boolean (*sc_reach_flags_fn)(SCNetworkReachabilityRef, SCNetworkReachabilityFlags *);
typedef CFDictionaryRef (*sc_copy_proxies_fn)(SCDynamicStoreRef);
typedef CFIndex (*cf_dict_count_fn)(CFDictionaryRef);
typedef const void *(*cf_dict_value_fn)(CFDictionaryRef, const void *);
typedef CFStringRef (*cf_string_create_fn)(CFAllocatorRef, const char *, CFStringEncoding);
typedef Boolean (*cf_number_get_fn)(CFNumberRef, CFNumberType, void *);
typedef void (*cf_release_fn)(CFTypeRef);

#undef htonl
#undef htons
#undef ntohl
#undef ntohs
uint32_t htonl(uint32_t);
uint16_t htons(uint16_t);
uint32_t ntohl(uint32_t);
uint16_t ntohs(uint16_t);

static int probe_gai(const char *label, getaddrinfo_fn gai, freeaddrinfo_fn free_gai) {
    struct addrinfo hints = {0};
    struct addrinfo *res = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int ret = gai("localhost", "80", &hints, &res);
    printf("compat gai %s ret=%d ptr=%p\n", label, ret, res);
    if (ret != 0 || res == 0) {
        return ret == 0 ? 3 : ret;
    }
    printf(
        "compat gai %s family=%d socktype=%d protocol=%d addrlen=%u\n",
        label,
        res->ai_family,
        res->ai_socktype,
        res->ai_protocol,
        (unsigned)res->ai_addrlen
    );
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    printf("compat gai %s socket=%d errno=%d\n", label, fd, errno);
    if (fd >= 0) {
        close(fd);
    }
    free_gai(res);
    return fd >= 0 ? 0 : 5;
}

static int probe_msg(const char *label, sendmsg_fn send_msg, recvmsg_fn recv_msg) {
    int sv[2] = {-1, -1};
    int pair_ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (pair_ret != 0) {
        printf("compat sendmsg %s socketpair=%d errno=%d\n", label, pair_ret, errno);
        return 7;
    }

    const char left[] = "msg-";
    const char right[] = "ok";
    struct iovec out_iov[2];
    out_iov[0].iov_base = (void *)left;
    out_iov[0].iov_len = 4;
    out_iov[1].iov_base = (void *)right;
    out_iov[1].iov_len = 2;
    struct msghdr out_msg = {0};
    out_msg.msg_iov = out_iov;
    out_msg.msg_iovlen = 2;

    char first[8] = {0};
    char second[8] = {0};
    struct iovec in_iov[2];
    in_iov[0].iov_base = first;
    in_iov[0].iov_len = 4;
    in_iov[1].iov_base = second;
    in_iov[1].iov_len = 2;
    struct msghdr in_msg = {0};
    in_msg.msg_iov = in_iov;
    in_msg.msg_iovlen = 2;

    long sent = (long)send_msg(sv[0], &out_msg, 0);
    long got = (long)recv_msg(sv[1], &in_msg, 0);
    printf("compat sendmsg %s sent=%ld recv=%ld text=%s%s flags=%d errno=%d\n", label, sent, got, first, second, in_msg.msg_flags, errno);
    close(sv[0]);
    close(sv[1]);
    if (sent != 6 || got != 6 || first[0] != 'm' || first[1] != 's' || first[2] != 'g' || first[3] != '-' || second[0] != 'o' || second[1] != 'k') {
        return 9;
    }
    return 0;
}

static int probe_inet_legacy(
    const char *label,
    inet_addr_fn inet_addr_ptr,
    inet_aton_fn inet_aton_ptr,
    inet_ntop_fn inet_ntop_ptr,
    htonl_fn htonl_ptr,
    htons_fn htons_ptr,
    ntohl_fn ntohl_ptr,
    ntohs_fn ntohs_ptr
) {
    struct in_addr parsed = {0};
    char text[INET_ADDRSTRLEN] = {0};
    in_addr_t loopback = inet_addr_ptr("127.0.0.1");
    int aton_ret = inet_aton_ptr("10.20.30.40", &parsed);
    const char *ntop_ret = inet_ntop_ptr(AF_INET, &parsed, text, sizeof(text));
    uint32_t net_long = htonl_ptr(0x11223344U);
    uint32_t host_long = ntohl_ptr(net_long);
    uint16_t net_short = htons_ptr(0x1357U);
    uint16_t host_short = ntohs_ptr(net_short);
    printf(
        "compat inet %s addr=0x%08x aton=%d text=%s ntop=%p htonl=0x%08x ntohl=0x%08x htons=0x%04x ntohs=0x%04x errno=%d\n",
        label,
        (unsigned)loopback,
        aton_ret,
        text,
        (void *)ntop_ret,
        (unsigned)net_long,
        (unsigned)host_long,
        (unsigned)net_short,
        (unsigned)host_short,
        errno
    );
    if (loopback != htonl_ptr(0x7f000001U) || aton_ret != 1 || ntop_ret == 0 || strcmp(text, "10.20.30.40") != 0 || host_long != 0x11223344U || host_short != 0x1357U) {
        return 11;
    }
    return 0;
}

static int probe_nameinfo(
    const char *label,
    getnameinfo_fn getnameinfo_ptr,
    inet_aton_fn inet_aton_ptr,
    htons_fn htons_ptr
) {
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
#ifdef __APPLE__
    sin.sin_len = sizeof(sin);
#endif
    sin.sin_family = AF_INET;
    sin.sin_port = htons_ptr(443);
    inet_aton_ptr("127.0.0.1", &sin.sin_addr);

    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo_ptr(
        (const struct sockaddr *)&sin,
        (socklen_t)sizeof(sin),
        host,
        sizeof(host),
        service,
        sizeof(service),
        NI_NUMERICHOST | NI_NUMERICSERV
    );
    printf("compat getnameinfo %s ret=%d host=%s service=%s errno=%d\n", label, ret, host, service, errno);
    if (ret != 0 || strcmp(host, "127.0.0.1") != 0 || strcmp(service, "443") != 0) {
        return 13;
    }
    return 0;
}

static int probe_ifaddrs(
    const char *label,
    getifaddrs_fn get_ifs,
    freeifaddrs_fn free_ifs,
    if_nametoindex_fn name_to_index
) {
    struct ifaddrs *ifs = 0;
    errno = 0;
    int ret = get_ifs(&ifs);
    int saved_errno = errno;
    int count = 0;
    int saw_lo = 0;
    char first[64] = {0};
    for (struct ifaddrs *cur = ifs; cur && count < 128; cur = cur->ifa_next) {
        if (count == 0 && cur->ifa_name) {
            snprintf(first, sizeof(first), "%s", cur->ifa_name);
        }
        if (cur->ifa_name && strcmp(cur->ifa_name, "lo0") == 0) {
            saw_lo = 1;
        }
        count++;
    }
    unsigned int lo_index = name_to_index("lo0");
    printf("compat ifaddrs %s ret=%d count=%d first=%s saw_lo=%d lo_index=%u errno=%d\n", label, ret, count, first, saw_lo, lo_index, saved_errno);
    if (ifs) {
        free_ifs(ifs);
    }
    if (ret != 0 || count <= 0 || !saw_lo || lo_index == 0) {
        return 15;
    }
    return 0;
}

static int probe_system_configuration(
    const char *label,
    sc_reach_create_fn reach_create,
    sc_reach_flags_fn reach_flags,
    sc_copy_proxies_fn copy_proxies,
    cf_dict_count_fn dict_count,
    cf_dict_value_fn dict_value,
    cf_string_create_fn string_create,
    cf_number_get_fn number_get,
    cf_release_fn release_value
) {
    SCNetworkReachabilityRef reach = reach_create(0, "example.com");
    SCNetworkReachabilityFlags flags = 0;
    Boolean flags_ok = reach ? reach_flags(reach, &flags) : 0;
    CFDictionaryRef proxies = copy_proxies(0);
    CFIndex proxy_count = proxies ? dict_count(proxies) : -1;
    CFStringRef http_key = string_create(0, "HTTPEnable", kCFStringEncodingUTF8);
    const void *http_value_ref = proxies && http_key ? dict_value(proxies, http_key) : 0;
    long long http_value = -1;
    Boolean number_ok = http_value_ref ? number_get((CFNumberRef)http_value_ref, kCFNumberLongLongType, &http_value) : 0;
    printf(
        "compat sc %s reach=%p flags_ok=%u flags=0x%x proxies=%p count=%ld http=%p number_ok=%u http_value=%lld\n",
        label,
        reach,
        (unsigned)flags_ok,
        (unsigned)flags,
        proxies,
        (long)proxy_count,
        http_value_ref,
        (unsigned)number_ok,
        http_value
    );
    if (http_key) {
        release_value(http_key);
    }
    if (proxies) {
        release_value(proxies);
    }
    if (reach) {
        release_value(reach);
    }
    if (!reach || !flags_ok || !proxies || proxy_count <= 0 || !http_value_ref || !number_ok || http_value < 0) {
        return 17;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    failures += probe_gai("static", getaddrinfo, freeaddrinfo);
    failures += probe_msg("static", sendmsg, recvmsg);
    failures += probe_inet_legacy("static", inet_addr, inet_aton, inet_ntop, htonl, htons, ntohl, ntohs);
    failures += probe_nameinfo("static", getnameinfo, inet_aton, htons);
    failures += probe_ifaddrs("static", getifaddrs, freeifaddrs, if_nametoindex);
    failures += probe_system_configuration(
        "static",
        SCNetworkReachabilityCreateWithName,
        SCNetworkReachabilityGetFlags,
        SCDynamicStoreCopyProxies,
        CFDictionaryGetCount,
        CFDictionaryGetValue,
        CFStringCreateWithCString,
        CFNumberGetValue,
        CFRelease
    );

    void *self = dlopen(NULL, RTLD_NOW);
    void *system_config = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    void *core_foundation = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    getaddrinfo_fn dyn_gai = (getaddrinfo_fn)dlsym(self, "getaddrinfo");
    freeaddrinfo_fn dyn_free = (freeaddrinfo_fn)dlsym(self, "freeaddrinfo");
    getnameinfo_fn dyn_nameinfo = (getnameinfo_fn)dlsym(self, "getnameinfo");
    getifaddrs_fn dyn_ifaddrs = (getifaddrs_fn)dlsym(self, "getifaddrs");
    freeifaddrs_fn dyn_freeifaddrs = (freeifaddrs_fn)dlsym(self, "freeifaddrs");
    if_nametoindex_fn dyn_ifindex = (if_nametoindex_fn)dlsym(self, "if_nametoindex");
    inet_addr_fn dyn_inet_addr = (inet_addr_fn)dlsym(self, "inet_addr");
    inet_aton_fn dyn_inet_aton = (inet_aton_fn)dlsym(self, "inet_aton");
    inet_ntop_fn dyn_inet_ntop = (inet_ntop_fn)dlsym(self, "inet_ntop");
    htonl_fn dyn_htonl = (htonl_fn)dlsym(self, "htonl");
    htons_fn dyn_htons = (htons_fn)dlsym(self, "htons");
    ntohl_fn dyn_ntohl = (ntohl_fn)dlsym(self, "ntohl");
    ntohs_fn dyn_ntohs = (ntohs_fn)dlsym(self, "ntohs");
    send_fn dyn_send = (send_fn)dlsym(self, "send");
    recv_fn dyn_recv = (recv_fn)dlsym(self, "recv");
    sendmsg_fn dyn_sendmsg = (sendmsg_fn)dlsym(self, "sendmsg");
    recvmsg_fn dyn_recvmsg = (recvmsg_fn)dlsym(self, "recvmsg");
    sc_reach_create_fn dyn_reach_create = (sc_reach_create_fn)dlsym(system_config, "SCNetworkReachabilityCreateWithName");
    sc_reach_flags_fn dyn_reach_flags = (sc_reach_flags_fn)dlsym(system_config, "SCNetworkReachabilityGetFlags");
    sc_copy_proxies_fn dyn_copy_proxies = (sc_copy_proxies_fn)dlsym(system_config, "SCDynamicStoreCopyProxies");
    cf_dict_count_fn dyn_dict_count = (cf_dict_count_fn)dlsym(core_foundation, "CFDictionaryGetCount");
    cf_dict_value_fn dyn_dict_value = (cf_dict_value_fn)dlsym(core_foundation, "CFDictionaryGetValue");
    cf_string_create_fn dyn_string_create = (cf_string_create_fn)dlsym(core_foundation, "CFStringCreateWithCString");
    cf_number_get_fn dyn_number_get = (cf_number_get_fn)dlsym(core_foundation, "CFNumberGetValue");
    cf_release_fn dyn_release = (cf_release_fn)dlsym(core_foundation, "CFRelease");
    printf(
        "compat dlsym network ptrs gai=%p free=%p nameinfo=%p ifaddrs=%p freeifaddrs=%p ifindex=%p reach=%p flags=%p proxies=%p dict_count=%p dict_value=%p cfstr=%p cfnum=%p cfrelease=%p inet_addr=%p inet_aton=%p inet_ntop=%p htonl=%p htons=%p ntohl=%p ntohs=%p send=%p recv=%p sendmsg=%p recvmsg=%p\n",
        (void *)dyn_gai,
        (void *)dyn_free,
        (void *)dyn_nameinfo,
        (void *)dyn_ifaddrs,
        (void *)dyn_freeifaddrs,
        (void *)dyn_ifindex,
        (void *)dyn_reach_create,
        (void *)dyn_reach_flags,
        (void *)dyn_copy_proxies,
        (void *)dyn_dict_count,
        (void *)dyn_dict_value,
        (void *)dyn_string_create,
        (void *)dyn_number_get,
        (void *)dyn_release,
        (void *)dyn_inet_addr,
        (void *)dyn_inet_aton,
        (void *)dyn_inet_ntop,
        (void *)dyn_htonl,
        (void *)dyn_htons,
        (void *)dyn_ntohl,
        (void *)dyn_ntohs,
        (void *)dyn_send,
        (void *)dyn_recv,
        (void *)dyn_sendmsg,
        (void *)dyn_recvmsg
    );
    if (dyn_gai == 0 || dyn_free == 0 || dyn_nameinfo == 0 || dyn_ifaddrs == 0 || dyn_freeifaddrs == 0 || dyn_ifindex == 0 || dyn_reach_create == 0 || dyn_reach_flags == 0 || dyn_copy_proxies == 0 || dyn_dict_count == 0 || dyn_dict_value == 0 || dyn_string_create == 0 || dyn_number_get == 0 || dyn_release == 0 || dyn_inet_addr == 0 || dyn_inet_aton == 0 || dyn_inet_ntop == 0 || dyn_htonl == 0 || dyn_htons == 0 || dyn_ntohl == 0 || dyn_ntohs == 0 || dyn_send == 0 || dyn_recv == 0 || dyn_sendmsg == 0 || dyn_recvmsg == 0) {
        return 4;
    }
    failures += probe_gai("dlsym", dyn_gai, dyn_free);
    failures += probe_msg("dlsym", dyn_sendmsg, dyn_recvmsg);
    failures += probe_inet_legacy("dlsym", dyn_inet_addr, dyn_inet_aton, dyn_inet_ntop, dyn_htonl, dyn_htons, dyn_ntohl, dyn_ntohs);
    failures += probe_nameinfo("dlsym", dyn_nameinfo, dyn_inet_aton, dyn_htons);
    failures += probe_ifaddrs("dlsym", dyn_ifaddrs, dyn_freeifaddrs, dyn_ifindex);
    failures += probe_system_configuration(
        "dlsym",
        dyn_reach_create,
        dyn_reach_flags,
        dyn_copy_proxies,
        dyn_dict_count,
        dyn_dict_value,
        dyn_string_create,
        dyn_number_get,
        dyn_release
    );

    int sv[2] = {-1, -1};
    int pair_ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    printf("compat socketpair ret=%d fd0=%d fd1=%d errno=%d\n", pair_ret, sv[0], sv[1], errno);
    if (pair_ret == 0) {
        const char msg[] = "net-ok";
        char buf[32] = {0};
        long sent = (long)dyn_send(sv[0], msg, sizeof(msg) - 1, 0);
        long got = (long)dyn_recv(sv[1], buf, sizeof(buf) - 1, 0);
        if (got >= 0 && got < (long)sizeof(buf)) {
            buf[got] = 0;
        }
        printf("compat socketpair io sent=%ld recv=%ld text=%s\n", sent, got, buf);
        close(sv[0]);
        close(sv[1]);
        if (sent != 6 || got != 6) {
            failures += 6;
        }
    } else {
        failures += 8;
    }

    dlclose(self);
    dlclose(system_config);
    dlclose(core_foundation);
    return failures == 0 ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 network fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-framework")
        .arg("CoreFoundation")
        .arg("-framework")
        .arg("SystemConfiguration")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 network fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 network fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_public_network_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_public_network_compat.c");
    let binary = out_dir.join("arm64_public_network_compat");
    fs::write(
        &source,
        r#"#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef const char *(*gai_strerror_fn)(int);
typedef int (*getnameinfo_fn)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
typedef int (*socket_fn)(int, int, int);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef int (*close_fn)(int);
typedef int (*fcntl_fn)(int, int, ...);
typedef int (*poll_fn)(struct pollfd *, nfds_t, int);
typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);

static int make_nonblocking(int fd, fcntl_fn fcntl_impl, int *old_flags) {
    errno = 0;
    int flags = fcntl_impl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    *old_flags = flags;
    return fcntl_impl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int finish_nonblocking_connect(
    int fd,
    int connect_ret,
    int connect_errno,
    poll_fn poll_impl,
    getsockopt_fn getsockopt_impl,
    int *poll_ret_out,
    short *revents_out,
    int *so_error_out
) {
    *poll_ret_out = -1;
    *revents_out = 0;
    *so_error_out = 0;
    if (connect_ret == 0) {
        return 0;
    }
    if (connect_errno != EINPROGRESS) {
        errno = connect_errno;
        return -1;
    }

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLOUT;
    errno = 0;
    int poll_ret = poll_impl(&pfd, 1, 3000);
    *poll_ret_out = poll_ret;
    *revents_out = pfd.revents;
    if (poll_ret <= 0) {
        if (poll_ret == 0) {
            errno = ETIMEDOUT;
        }
        return -1;
    }

    int so_error = 0;
    socklen_t so_len = sizeof(so_error);
    if (getsockopt_impl(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0) {
        return -1;
    }
    *so_error_out = so_error;
    if (so_error != 0) {
        errno = so_error;
        return -1;
    }
    return 0;
}

static void sanitize_preview(char *buf, long len) {
    if (len < 0) {
        return;
    }
    for (long i = 0; i < len; i++) {
        if (buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\t') {
            buf[i] = ' ';
        }
    }
}

static int probe_public_network(
    const char *label,
    getaddrinfo_fn gai_impl,
    freeaddrinfo_fn free_impl,
    gai_strerror_fn gai_error_impl,
    getnameinfo_fn nameinfo_impl,
    socket_fn socket_impl,
    connect_fn connect_impl,
    send_fn send_impl,
    recv_fn recv_impl,
    close_fn close_impl,
    fcntl_fn fcntl_impl,
    poll_fn poll_impl,
    getsockopt_fn getsockopt_impl
) {
    const char *host = "example.com";
    const char *service = "80";
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = 0;
    errno = 0;
    int gai_ret = gai_impl(host, service, &hints, &res);
    const char *gai_text = gai_ret == 0 ? "ok" : gai_error_impl(gai_ret);
    printf("compat publicnet %s resolve host=%s service=%s ret=%d err=%s ptr=%p errno=%d\n",
           label, host, service, gai_ret, gai_text ? gai_text : "<null>", (void *)res, errno);
    if (gai_ret != 0 || res == 0) {
        printf("compat publicnet %s summary attempted=1 resolved=0 connected=0 sent=-1 recv=-1 reason=gai:%d:%s\n",
               label, gai_ret, gai_text ? gai_text : "<null>");
        return 0;
    }

    char numeric_host[NI_MAXHOST] = {0};
    char numeric_service[NI_MAXSERV] = {0};
    int ni_ret = nameinfo_impl(res->ai_addr, res->ai_addrlen, numeric_host, sizeof(numeric_host), numeric_service, sizeof(numeric_service), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("compat publicnet %s resolved family=%d socktype=%d protocol=%d addrlen=%u nameinfo=%d addr=%s port=%s errno=%d\n",
           label, res->ai_family, res->ai_socktype, res->ai_protocol, (unsigned)res->ai_addrlen, ni_ret, numeric_host, numeric_service, errno);

    errno = 0;
    int fd = socket_impl(res->ai_family, res->ai_socktype, res->ai_protocol);
    int socket_errno = errno;
    printf("compat publicnet %s socket fd=%d errno=%d\n", label, fd, socket_errno);
    if (fd < 0) {
        printf("compat publicnet %s summary attempted=1 resolved=1 connected=0 sent=-1 recv=-1 reason=socket:%d\n",
               label, socket_errno);
        free_impl(res);
        return 0;
    }

    int old_flags = 0;
    int nb_ret = make_nonblocking(fd, fcntl_impl, &old_flags);
    int nb_errno = errno;
    int connect_ret = -1;
    int connect_errno = nb_errno;
    int poll_ret = -1;
    short revents = 0;
    int so_error = 0;
    int connected = 0;
    if (nb_ret == 0) {
        errno = 0;
        connect_ret = connect_impl(fd, res->ai_addr, res->ai_addrlen);
        connect_errno = errno;
        connected = finish_nonblocking_connect(fd, connect_ret, connect_errno, poll_impl, getsockopt_impl, &poll_ret, &revents, &so_error) == 0;
    }
    int final_connect_errno = connected ? 0 : errno;
    printf("compat publicnet %s connect nb=%d/%d ret=%d errno=%d poll=%d revents=0x%x so_error=%d connected=%d final_errno=%d\n",
           label, nb_ret, nb_errno, connect_ret, connect_errno, poll_ret, (unsigned)revents, so_error, connected, final_connect_errno);

    long sent = -1;
    long got = -1;
    char preview[256];
    memset(preview, 0, sizeof(preview));
    const char *reason = connected ? "ok" : "connect";
    if (connected) {
        (void)fcntl_impl(fd, F_SETFL, old_flags);
        const char request[] =
            "GET / HTTP/1.0\r\n"
            "Host: example.com\r\n"
            "User-Agent: compatra-publicnet\r\n"
            "Connection: close\r\n"
            "\r\n";
        errno = 0;
        sent = (long)send_impl(fd, request, sizeof(request) - 1, 0);
        int send_errno = errno;
        printf("compat publicnet %s send bytes=%ld errno=%d\n", label, sent, send_errno);
        if (sent > 0) {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = fd;
            pfd.events = POLLIN;
            errno = 0;
            int read_poll = poll_impl(&pfd, 1, 3000);
            int read_poll_errno = errno;
            if (read_poll > 0) {
                errno = 0;
                got = (long)recv_impl(fd, preview, sizeof(preview) - 1, 0);
                int recv_errno = errno;
                if (got > 0 && got < (long)sizeof(preview)) {
                    preview[got] = 0;
                }
                sanitize_preview(preview, got);
                printf("compat publicnet %s recv poll=%d revents=0x%x bytes=%ld errno=%d preview=%.*s\n",
                       label, read_poll, (unsigned)pfd.revents, got, recv_errno, got > 96 ? 96 : (int)(got > 0 ? got : 0), preview);
                reason = got > 0 ? "response" : "recv";
            } else {
                printf("compat publicnet %s recv poll=%d revents=0x%x errno=%d preview=\n",
                       label, read_poll, (unsigned)pfd.revents, read_poll_errno);
                reason = read_poll == 0 ? "recv-timeout" : "poll";
            }
        } else {
            reason = "send";
        }
    }

    printf("compat publicnet %s summary attempted=1 resolved=1 connected=%d sent=%ld recv=%ld reason=%s addr=%s port=%s\n",
           label, connected, sent, got, reason, numeric_host, numeric_service);
    close_impl(fd);
    free_impl(res);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += probe_public_network(
        "static",
        getaddrinfo,
        freeaddrinfo,
        gai_strerror,
        getnameinfo,
        socket,
        connect,
        send,
        recv,
        close,
        fcntl,
        poll,
        getsockopt
    );

    void *self = dlopen(NULL, RTLD_NOW);
    getaddrinfo_fn dyn_gai = (getaddrinfo_fn)dlsym(self, "getaddrinfo");
    freeaddrinfo_fn dyn_free = (freeaddrinfo_fn)dlsym(self, "freeaddrinfo");
    gai_strerror_fn dyn_gai_error = (gai_strerror_fn)dlsym(self, "gai_strerror");
    getnameinfo_fn dyn_nameinfo = (getnameinfo_fn)dlsym(self, "getnameinfo");
    socket_fn dyn_socket = (socket_fn)dlsym(self, "socket");
    connect_fn dyn_connect = (connect_fn)dlsym(self, "connect");
    send_fn dyn_send = (send_fn)dlsym(self, "send");
    recv_fn dyn_recv = (recv_fn)dlsym(self, "recv");
    close_fn dyn_close = (close_fn)dlsym(self, "close");
    fcntl_fn dyn_fcntl = (fcntl_fn)dlsym(self, "fcntl");
    poll_fn dyn_poll = (poll_fn)dlsym(self, "poll");
    getsockopt_fn dyn_getsockopt = (getsockopt_fn)dlsym(self, "getsockopt");
    printf("compat publicnet dlsym ptrs gai=%p free=%p gaierr=%p nameinfo=%p socket=%p connect=%p send=%p recv=%p close=%p fcntl=%p poll=%p getopt=%p\n",
           (void *)dyn_gai, (void *)dyn_free, (void *)dyn_gai_error, (void *)dyn_nameinfo, (void *)dyn_socket, (void *)dyn_connect, (void *)dyn_send, (void *)dyn_recv, (void *)dyn_close, (void *)dyn_fcntl, (void *)dyn_poll, (void *)dyn_getsockopt);
    if (dyn_gai && dyn_free && dyn_gai_error && dyn_nameinfo && dyn_socket && dyn_connect && dyn_send && dyn_recv && dyn_close && dyn_fcntl && dyn_poll && dyn_getsockopt) {
        failures += probe_public_network(
            "dlsym",
            dyn_gai,
            dyn_free,
            dyn_gai_error,
            dyn_nameinfo,
            dyn_socket,
            dyn_connect,
            dyn_send,
            dyn_recv,
            dyn_close,
            dyn_fcntl,
            dyn_poll,
            dyn_getsockopt
        );
    } else {
        printf("compat publicnet dlsym summary attempted=0 resolved=0 connected=0 sent=-1 recv=-1 reason=missing-dlsym\n");
    }
    dlclose(self);
    printf("compat publicnet final failures=%d\n", failures);
    return 0;
}
"#,
    )
    .expect("failed to write generated arm64 public network fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 public network fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 public network fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_network_matrix_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_network_matrix_compat.c");
    let binary = out_dir.join("arm64_network_matrix_compat");
    fs::write(
        &source,
        r#"#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int (*accept_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef const char *(*gai_strerror_fn)(int);
typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef int (*getpeername_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*getsockname_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);
typedef int (*listen_fn)(int, int);
typedef int (*poll_fn)(struct pollfd *, nfds_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef int (*shutdown_fn)(int, int);
typedef int (*socket_fn)(int, int, int);

#undef htonl
#undef htons
#undef ntohl
#undef ntohs
uint32_t htonl(uint32_t);
uint16_t htons(uint16_t);
uint32_t ntohl(uint32_t);
uint16_t ntohs(uint16_t);

static void loopback_addr(struct sockaddr_in *sin, unsigned short port) {
    memset(sin, 0, sizeof(*sin));
#ifdef __APPLE__
    sin->sin_len = sizeof(*sin);
#endif
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(0x7f000001U);
}

static unsigned short sockaddr_port(const struct sockaddr_in *sin) {
    return ntohs(sin->sin_port);
}

static int text_eq(const char *value, const char *expected, long len) {
    if (len < 0) {
        return 0;
    }
    long i = 0;
    for (; expected[i] != 0; i++) {
        if (i >= len || value[i] != expected[i]) {
            return 0;
        }
    }
    return len == i;
}

static int probe_resolver(const char *label, getaddrinfo_fn gai, freeaddrinfo_fn free_gai, gai_strerror_fn gai_err) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    struct addrinfo *res = 0;
    int ok_ret = gai("127.0.0.1", "443", &hints, &res);
    int family = res ? res->ai_family : -1;
    int socktype = res ? res->ai_socktype : -1;
    unsigned addrlen = res ? (unsigned)res->ai_addrlen : 0;
    printf("compat netmatrix resolver %s ok_ret=%d ptr=%p family=%d socktype=%d addrlen=%u\n", label, ok_ret, res, family, socktype, addrlen);
    if (res) {
        free_gai(res);
    }

    struct addrinfo *bad_res = 0;
    int bad_ret = gai("not-a-numeric-address", "443", &hints, &bad_res);
    const char *message = gai_err(bad_ret);
    printf("compat netmatrix resolver %s bad_ret=%d err=%s bad_ptr=%p\n", label, bad_ret, message ? message : "<null>", bad_res);
    if (bad_res) {
        free_gai(bad_res);
    }
    return ok_ret == 0 && family == AF_INET && bad_ret != 0 && message && message[0] ? 0 : 10;
}

static int probe_udp(
    const char *label,
    socket_fn socket_impl,
    bind_fn bind_impl,
    getsockname_fn getsockname_impl,
    sendto_fn sendto_impl,
    recvfrom_fn recvfrom_impl,
    sendmsg_fn sendmsg_impl,
    recvmsg_fn recvmsg_impl,
    setsockopt_fn setsockopt_impl,
    getsockopt_fn getsockopt_impl,
    poll_fn poll_impl
) {
    int failures = 0;
    int recv_fd = socket_impl(AF_INET, SOCK_DGRAM, 0);
    int send_fd = socket_impl(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    int set_ret = recv_fd >= 0 ? setsockopt_impl(recv_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) : -1;
    int opt_value = 0;
    socklen_t opt_len = sizeof(opt_value);
    int get_ret = recv_fd >= 0 ? getsockopt_impl(recv_fd, SOL_SOCKET, SO_REUSEADDR, &opt_value, &opt_len) : -1;

    struct sockaddr_in recv_addr;
    struct sockaddr_in send_addr;
    loopback_addr(&recv_addr, 0);
    loopback_addr(&send_addr, 0);
    int recv_bind = recv_fd >= 0 ? bind_impl(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) : -1;
    int send_bind = send_fd >= 0 ? bind_impl(send_fd, (struct sockaddr *)&send_addr, sizeof(send_addr)) : -1;
    socklen_t recv_addr_len = sizeof(recv_addr);
    socklen_t send_addr_len = sizeof(send_addr);
    int recv_name = recv_fd >= 0 ? getsockname_impl(recv_fd, (struct sockaddr *)&recv_addr, &recv_addr_len) : -1;
    int send_name = send_fd >= 0 ? getsockname_impl(send_fd, (struct sockaddr *)&send_addr, &send_addr_len) : -1;

    struct pollfd pfd;
    pfd.fd = recv_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int poll_empty = recv_fd >= 0 ? poll_impl(&pfd, 1, 0) : -1;
    short empty_revents = pfd.revents;

    const char udp_text[] = "udp-one";
    long sent = send_fd >= 0 ? (long)sendto_impl(send_fd, udp_text, sizeof(udp_text) - 1, 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) : -1;
    pfd.fd = recv_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int poll_ready = recv_fd >= 0 ? poll_impl(&pfd, 1, 1000) : -1;
    short ready_revents = pfd.revents;

    char recv_buf[64] = {0};
    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    socklen_t src_len = sizeof(src_addr);
    long got = recv_fd >= 0 ? (long)recvfrom_impl(recv_fd, recv_buf, sizeof(recv_buf) - 1, 0, (struct sockaddr *)&src_addr, &src_len) : -1;
    if (got >= 0 && got < (long)sizeof(recv_buf)) {
        recv_buf[got] = 0;
    }
    printf(
        "compat netmatrix udp %s fds=%d,%d bind=%d/%d name=%d/%d ports=%u/%u opt=%d/%d/%d/%u poll=%d/0x%x,%d/0x%x sendto=%ld recvfrom=%ld text=%s srclen=%u srcport=%u errno=%d\n",
        label,
        recv_fd,
        send_fd,
        recv_bind,
        send_bind,
        recv_name,
        send_name,
        sockaddr_port(&recv_addr),
        sockaddr_port(&send_addr),
        set_ret,
        get_ret,
        opt_value,
        (unsigned)opt_len,
        poll_empty,
        (unsigned)empty_revents,
        poll_ready,
        (unsigned)ready_revents,
        sent,
        got,
        recv_buf,
        (unsigned)src_len,
        sockaddr_port(&src_addr),
        errno
    );
    if (recv_fd < 0 || send_fd < 0 || recv_bind != 0 || send_bind != 0 || recv_name != 0 || send_name != 0 || sockaddr_port(&recv_addr) == 0 || sockaddr_port(&send_addr) == 0 || set_ret != 0 || get_ret != 0 || opt_len == 0 || poll_empty != 0 || poll_ready <= 0 || sent != 7 || got != 7 || !text_eq(recv_buf, "udp-one", got) || src_len == 0 || sockaddr_port(&src_addr) == 0) {
        failures += 20;
    }

    const char left[] = "msg-";
    const char right[] = "udp";
    struct iovec out_iov[2];
    out_iov[0].iov_base = (void *)left;
    out_iov[0].iov_len = 4;
    out_iov[1].iov_base = (void *)right;
    out_iov[1].iov_len = 3;
    struct msghdr out_msg;
    memset(&out_msg, 0, sizeof(out_msg));
    out_msg.msg_name = &recv_addr;
    out_msg.msg_namelen = sizeof(recv_addr);
    out_msg.msg_iov = out_iov;
    out_msg.msg_iovlen = 2;
    long msg_sent = send_fd >= 0 ? (long)sendmsg_impl(send_fd, &out_msg, 0) : -1;

    char msg_a[8] = {0};
    char msg_b[8] = {0};
    struct iovec in_iov[2];
    in_iov[0].iov_base = msg_a;
    in_iov[0].iov_len = 4;
    in_iov[1].iov_base = msg_b;
    in_iov[1].iov_len = 3;
    struct sockaddr_in msg_src;
    memset(&msg_src, 0, sizeof(msg_src));
    struct msghdr in_msg;
    memset(&in_msg, 0, sizeof(in_msg));
    in_msg.msg_name = &msg_src;
    in_msg.msg_namelen = sizeof(msg_src);
    in_msg.msg_iov = in_iov;
    in_msg.msg_iovlen = 2;
    long msg_got = recv_fd >= 0 ? (long)recvmsg_impl(recv_fd, &in_msg, 0) : -1;
    printf(
        "compat netmatrix udp-msg %s sendmsg=%ld recvmsg=%ld text=%s%s namelen=%u srcport=%u flags=0x%x errno=%d\n",
        label,
        msg_sent,
        msg_got,
        msg_a,
        msg_b,
        (unsigned)in_msg.msg_namelen,
        sockaddr_port(&msg_src),
        (unsigned)in_msg.msg_flags,
        errno
    );
    if (msg_sent != 7 || msg_got != 7 || msg_a[0] != 'm' || msg_a[1] != 's' || msg_a[2] != 'g' || msg_a[3] != '-' || msg_b[0] != 'u' || msg_b[1] != 'd' || msg_b[2] != 'p' || in_msg.msg_namelen == 0 || sockaddr_port(&msg_src) == 0) {
        failures += 30;
    }

    if (recv_fd >= 0) {
        close(recv_fd);
    }
    if (send_fd >= 0) {
        close(send_fd);
    }
    return failures;
}

static int probe_tcp(
    const char *label,
    socket_fn socket_impl,
    setsockopt_fn setsockopt_impl,
    bind_fn bind_impl,
    getsockname_fn getsockname_impl,
    listen_fn listen_impl,
    connect_fn connect_impl,
    accept_fn accept_impl,
    getpeername_fn getpeername_impl,
    send_fn send_impl,
    recv_fn recv_impl,
    shutdown_fn shutdown_impl
) {
    int failures = 0;
    int listener = socket_impl(AF_INET, SOCK_STREAM, 0);
    int client = socket_impl(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    int set_ret = listener >= 0 ? setsockopt_impl(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) : -1;
    struct sockaddr_in listen_addr;
    loopback_addr(&listen_addr, 0);
    int bind_ret = listener >= 0 ? bind_impl(listener, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) : -1;
    socklen_t listen_len = sizeof(listen_addr);
    int name_ret = listener >= 0 ? getsockname_impl(listener, (struct sockaddr *)&listen_addr, &listen_len) : -1;
    int listen_ret = listener >= 0 ? listen_impl(listener, 1) : -1;
    int connect_ret = client >= 0 ? connect_impl(client, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) : -1;
    struct sockaddr_in accepted_peer;
    memset(&accepted_peer, 0, sizeof(accepted_peer));
    socklen_t accepted_peer_len = sizeof(accepted_peer);
    int accepted = listener >= 0 ? accept_impl(listener, (struct sockaddr *)&accepted_peer, &accepted_peer_len) : -1;
    struct sockaddr_in accepted_peer_check;
    memset(&accepted_peer_check, 0, sizeof(accepted_peer_check));
    socklen_t accepted_peer_check_len = sizeof(accepted_peer_check);
    int peer_ret = accepted >= 0 ? getpeername_impl(accepted, (struct sockaddr *)&accepted_peer_check, &accepted_peer_check_len) : -1;

    const char client_text[] = "tcp-ok";
    char server_buf[32] = {0};
    long client_sent = client >= 0 ? (long)send_impl(client, client_text, sizeof(client_text) - 1, 0) : -1;
    long server_got = accepted >= 0 ? (long)recv_impl(accepted, server_buf, sizeof(server_buf) - 1, 0) : -1;
    if (server_got >= 0 && server_got < (long)sizeof(server_buf)) {
        server_buf[server_got] = 0;
    }
    const char server_text[] = "reply";
    char client_buf[32] = {0};
    long server_sent = accepted >= 0 ? (long)send_impl(accepted, server_text, sizeof(server_text) - 1, 0) : -1;
    long client_got = client >= 0 ? (long)recv_impl(client, client_buf, sizeof(client_buf) - 1, 0) : -1;
    if (client_got >= 0 && client_got < (long)sizeof(client_buf)) {
        client_buf[client_got] = 0;
    }
    int shutdown_ret = client >= 0 ? shutdown_impl(client, SHUT_RDWR) : -1;

    printf(
        "compat netmatrix tcp %s fds=%d,%d,%d set=%d bind=%d name=%d port=%u listen=%d connect=%d accept=%d peer=%d peerlen=%u peerport=%u sendrecv=%ld/%ld/%s reply=%ld/%ld/%s shutdown=%d errno=%d\n",
        label,
        listener,
        client,
        accepted,
        set_ret,
        bind_ret,
        name_ret,
        sockaddr_port(&listen_addr),
        listen_ret,
        connect_ret,
        accepted,
        peer_ret,
        (unsigned)accepted_peer_check_len,
        sockaddr_port(&accepted_peer_check),
        client_sent,
        server_got,
        server_buf,
        server_sent,
        client_got,
        client_buf,
        shutdown_ret,
        errno
    );
    if (listener < 0 || client < 0 || accepted < 0 || set_ret != 0 || bind_ret != 0 || name_ret != 0 || sockaddr_port(&listen_addr) == 0 || listen_ret != 0 || connect_ret != 0 || peer_ret != 0 || accepted_peer_check_len == 0 || sockaddr_port(&accepted_peer_check) == 0 || client_sent != 6 || server_got != 6 || !text_eq(server_buf, "tcp-ok", server_got) || server_sent != 5 || client_got != 5 || !text_eq(client_buf, "reply", client_got) || shutdown_ret != 0) {
        failures += 40;
    }

    if (accepted >= 0) {
        close(accepted);
    }
    if (client >= 0) {
        close(client);
    }
    if (listener >= 0) {
        close(listener);
    }
    return failures;
}

int main(void) {
    int failures = 0;
    failures += probe_resolver("static", getaddrinfo, freeaddrinfo, gai_strerror);
    failures += probe_udp("static", socket, bind, getsockname, sendto, recvfrom, sendmsg, recvmsg, setsockopt, getsockopt, poll);

    void *self = dlopen(NULL, RTLD_NOW);
    accept_fn dyn_accept = (accept_fn)dlsym(self, "accept");
    bind_fn dyn_bind = (bind_fn)dlsym(self, "bind");
    connect_fn dyn_connect = (connect_fn)dlsym(self, "connect");
    freeaddrinfo_fn dyn_free = (freeaddrinfo_fn)dlsym(self, "freeaddrinfo");
    gai_strerror_fn dyn_gai_err = (gai_strerror_fn)dlsym(self, "gai_strerror");
    getaddrinfo_fn dyn_gai = (getaddrinfo_fn)dlsym(self, "getaddrinfo");
    getpeername_fn dyn_getpeername = (getpeername_fn)dlsym(self, "getpeername");
    getsockname_fn dyn_getsockname = (getsockname_fn)dlsym(self, "getsockname");
    getsockopt_fn dyn_getsockopt = (getsockopt_fn)dlsym(self, "getsockopt");
    listen_fn dyn_listen = (listen_fn)dlsym(self, "listen");
    poll_fn dyn_poll = (poll_fn)dlsym(self, "poll");
    recv_fn dyn_recv = (recv_fn)dlsym(self, "recv");
    recvfrom_fn dyn_recvfrom = (recvfrom_fn)dlsym(self, "recvfrom");
    recvmsg_fn dyn_recvmsg = (recvmsg_fn)dlsym(self, "recvmsg");
    send_fn dyn_send = (send_fn)dlsym(self, "send");
    sendmsg_fn dyn_sendmsg = (sendmsg_fn)dlsym(self, "sendmsg");
    sendto_fn dyn_sendto = (sendto_fn)dlsym(self, "sendto");
    setsockopt_fn dyn_setsockopt = (setsockopt_fn)dlsym(self, "setsockopt");
    shutdown_fn dyn_shutdown = (shutdown_fn)dlsym(self, "shutdown");
    socket_fn dyn_socket = (socket_fn)dlsym(self, "socket");
    printf(
        "compat netmatrix dlsym accept=%p bind=%p connect=%p gai=%p gaierr=%p getpeer=%p getsock=%p getopt=%p listen=%p poll=%p recv=%p recvfrom=%p recvmsg=%p send=%p sendmsg=%p sendto=%p setopt=%p shutdown=%p socket=%p\n",
        (void *)dyn_accept,
        (void *)dyn_bind,
        (void *)dyn_connect,
        (void *)dyn_gai,
        (void *)dyn_gai_err,
        (void *)dyn_getpeername,
        (void *)dyn_getsockname,
        (void *)dyn_getsockopt,
        (void *)dyn_listen,
        (void *)dyn_poll,
        (void *)dyn_recv,
        (void *)dyn_recvfrom,
        (void *)dyn_recvmsg,
        (void *)dyn_send,
        (void *)dyn_sendmsg,
        (void *)dyn_sendto,
        (void *)dyn_setsockopt,
        (void *)dyn_shutdown,
        (void *)dyn_socket
    );
    if (!dyn_accept || !dyn_bind || !dyn_connect || !dyn_free || !dyn_gai_err || !dyn_gai || !dyn_getpeername || !dyn_getsockname || !dyn_getsockopt || !dyn_listen || !dyn_poll || !dyn_recv || !dyn_recvfrom || !dyn_recvmsg || !dyn_send || !dyn_sendmsg || !dyn_sendto || !dyn_setsockopt || !dyn_shutdown || !dyn_socket) {
        failures += 50;
    } else {
        failures += probe_resolver("dlsym", dyn_gai, dyn_free, dyn_gai_err);
        failures += probe_udp("dlsym", dyn_socket, dyn_bind, dyn_getsockname, dyn_sendto, dyn_recvfrom, dyn_sendmsg, dyn_recvmsg, dyn_setsockopt, dyn_getsockopt, dyn_poll);
        failures += probe_tcp("dlsym", dyn_socket, dyn_setsockopt, dyn_bind, dyn_getsockname, dyn_listen, dyn_connect, dyn_accept, dyn_getpeername, dyn_send, dyn_recv, dyn_shutdown);
    }
    dlclose(self);
    printf("compat netmatrix summary failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 network matrix fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 network matrix fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 network matrix fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_fd_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_fd_compat.c");
    let binary = out_dir.join("arm64_fd_compat");
    let data_file = out_dir.join("arm64_fd_compat.tmp");
    fs::write(
        &source,
        format!(
            r#"#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define SYS_PIPE 0x200002A
#define SYS_IOCTL 0x2000036
#define SYS_FSYNC 0x200005F
#define SYS_STATFS64 0x2000159
#define SYS_FSTATFS64 0x200015A
#define SYS_OPENAT 0x20001CF
#define SYS_FACCESSAT 0x20001D2
#define SYS_FSTATAT 0x20001D5
#define SYS_READ_NOCANCEL 0x200018C
#define SYS_WRITE_NOCANCEL 0x200018D
#define SYS_OPEN_NOCANCEL 0x200018E
#define SYS_CLOSE_NOCANCEL 0x200018F
#define SYS_FCNTL_NOCANCEL 0x2000196

typedef int (*pipe_fn)(int *);
typedef int (*open_fn)(const char *, int, ...);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef int (*close_fn)(int);
typedef ssize_t (*readv_fn)(int, const struct iovec *, int);
typedef ssize_t (*writev_fn)(int, const struct iovec *, int);
typedef ssize_t (*pread_fn)(int, void *, size_t, off_t);
typedef ssize_t (*pwrite_fn)(int, const void *, size_t, off_t);
typedef off_t (*lseek_fn)(int, off_t, int);
typedef int (*select_fn)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);

static void clear_fdset(fd_set *set) {{
    unsigned char *bytes = (unsigned char *)set;
    for (unsigned long i = 0; i < sizeof(*set); i++) {{
        bytes[i] = 0;
    }}
}}

static int text_is(const char *text, const char *expected, unsigned long len) {{
    for (unsigned long i = 0; i < len; i++) {{
        if (text[i] != expected[i]) {{
            return 0;
        }}
    }}
    return 1;
}}

static void fixture_dir_from_argv0(const char *argv0, char *out, size_t out_len) {{
    if (out_len == 0) {{
        return;
    }}
    (void)argv0;
    snprintf(out, out_len, ".");
}}

static void join_path(const char *base, const char *name, char *out, size_t out_len) {{
    if (strcmp(base, "/") == 0) {{
        snprintf(out, out_len, "/%s", name);
    }} else {{
        snprintf(out, out_len, "%s/%s", base, name);
    }}
}}

static void fixture_path_from_argv0(const char *argv0, const char *name, char *out, size_t out_len) {{
    char dir[4096] = {{0}};
    fixture_dir_from_argv0(argv0, dir, sizeof(dir));
    join_path(dir, name, out, out_len);
}}

static void fixture_dir_from_optional_arg(int argc, char **argv, const char *argv0, char *out, size_t out_len) {{
    if (argc > 1 && argv && argv[1] && argv[1][0]) {{
        snprintf(out, out_len, "%s", argv[1]);
    }} else {{
        fixture_dir_from_argv0(argv0, out, out_len);
    }}
}}

static long compatra_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    asm volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
        : "memory", "cc");
    return x0;
}}

static long compatra_pipe_syscall(int fds[2]) {{
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = 0;
    register long x16 __asm__("x16") = SYS_PIPE;
    asm volatile(
        "svc #0x80"
        : "+r"(x0), "+r"(x1)
        : "r"(x16)
        : "memory", "cc");
    fds[0] = (int)x0;
    fds[1] = (int)x1;
    return x0 < 0 ? -1 : 0;
}}

static int pipe_vec_roundtrip(const char *label, pipe_fn pipe_impl, writev_fn writev_impl, readv_fn readv_impl) {{
    int fds[2] = {{-1, -1}};
    int pipe_ret = pipe_impl(fds);
    printf("compat fd %s pipe ret=%d fds=%d,%d errno=%d\n", label, pipe_ret, fds[0], fds[1], errno);
    if (pipe_ret != 0) {{
        return 10;
    }}

    const char left[] = "vec-";
    const char right[] = "ok";
    struct iovec out[2];
    out[0].iov_base = (void *)left;
    out[0].iov_len = 4;
    out[1].iov_base = (void *)right;
    out[1].iov_len = 2;

    char first[8] = {{0}};
    char second[8] = {{0}};
    struct iovec in[2];
    in[0].iov_base = first;
    in[0].iov_len = 4;
    in[1].iov_base = second;
    in[1].iov_len = 2;

    long written = (long)writev_impl(fds[1], out, 2);
    long read_count = (long)readv_impl(fds[0], in, 2);
    printf("compat fd %s writev=%ld readv=%ld text=%s%s errno=%d\n", label, written, read_count, first, second, errno);
    close(fds[0]);
    close(fds[1]);
    if (written != 6 || read_count != 6 || !text_is(first, "vec-", 4) || !text_is(second, "ok", 2)) {{
        return 11;
    }}
    return 0;
}}

int main(int argc, char **argv) {{
    int failures = 0;
    const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : ".";
    char data_file[4096] = {{0}};
    char data_dir[4096] = {{0}};
    fixture_dir_from_optional_arg(argc, argv, argv0, data_dir, sizeof(data_dir));
    join_path(data_dir, "arm64_fd_compat.tmp", data_file, sizeof(data_file));
    printf(
        "compat fd paths argc=%d argv1=%s data_dir=%s data_file=%s\n",
        argc,
        (argc > 1 && argv && argv[1]) ? argv[1] : "<none>",
        data_dir,
        data_file
    );
    failures += pipe_vec_roundtrip("static", pipe, writev, readv);

    int select_fds[2] = {{-1, -1}};
    int select_pipe = pipe(select_fds);
    fd_set read_set;
    clear_fdset(&read_set);
    FD_SET(select_fds[0], &read_set);
    struct timeval immediate = {{0, 0}};
    int select_empty = select(select_fds[0] + 1, &read_set, 0, 0, &immediate);
    write(select_fds[1], "S", 1);
    clear_fdset(&read_set);
    FD_SET(select_fds[0], &read_set);
    struct timeval short_wait = {{0, 100000}};
    int select_ready = select(select_fds[0] + 1, &read_set, 0, 0, &short_wait);
    int select_isset = FD_ISSET(select_fds[0], &read_set) ? 1 : 0;
    char select_byte = 0;
    read(select_fds[0], &select_byte, 1);
    printf("compat fd select pipe=%d empty=%d ready=%d isset=%d byte=%c errno=%d\n", select_pipe, select_empty, select_ready, select_isset, select_byte, errno);
    if (select_pipe != 0 || select_empty != 0 || select_ready != 1 || select_isset != 1 || select_byte != 'S') {{
        failures += 20;
    }}

    int dup_fds[2] = {{-1, -1}};
    pipe(dup_fds);
    int dup_fd = dup(dup_fds[1]);
    write(dup_fd, "D", 1);
    char dup_byte = 0;
    read(dup_fds[0], &dup_byte, 1);
    int dup2_target = dup(dup_fds[1]);
    int dup2_ret = dup2(dup_fds[1], dup2_target);
    write(dup2_target, "E", 1);
    char dup2_byte = 0;
    read(dup_fds[0], &dup2_byte, 1);
    printf("compat fd dup fd=%d byte=%c dup2_ret=%d target=%d byte=%c errno=%d\n", dup_fd, dup_byte, dup2_ret, dup2_target, dup2_byte, errno);
    if (dup_fd < 0 || dup_byte != 'D' || dup2_ret != dup2_target || dup2_byte != 'E') {{
        failures += 30;
    }}
    close(dup_fd);
    close(dup2_target);
    close(dup_fds[0]);
    close(dup_fds[1]);

    int file_fd = open(data_file, O_CREAT | O_TRUNC | O_RDWR, 0600);
    long pwrite_count = (long)pwrite(file_fd, "pos-ok", 6, 2);
    long seek_pos = (long)lseek(file_fd, 2, SEEK_SET);
    char positioned[16] = {{0}};
    long pread_count = (long)pread(file_fd, positioned, 6, 2);
    printf("compat fd positioned fd=%d pwrite=%ld lseek=%ld pread=%ld text=%s errno=%d\n", file_fd, pwrite_count, seek_pos, pread_count, positioned, errno);
    if (file_fd < 0 || pwrite_count != 6 || seek_pos != 2 || pread_count != 6 || !text_is(positioned, "pos-ok", 6)) {{
        failures += 40;
    }}

    int meta_fds[2] = {{-1, -1}};
    int meta_pipe = pipe(meta_fds);
    int meta_available = -1;
    if (meta_pipe == 0) {{
        write(meta_fds[1], "IO", 2);
    }}
    int ioctl_ret = meta_pipe == 0 ? ioctl(meta_fds[0], FIONREAD, &meta_available) : -1;
    char meta_buf[4] = {{0}};
    if (meta_pipe == 0) {{
        read(meta_fds[0], meta_buf, 2);
        close(meta_fds[0]);
        close(meta_fds[1]);
    }}
    int fsync_ret = file_fd >= 0 ? fsync(file_fd) : -1;
    struct statfs path_fs = {{0}};
    struct statfs fd_fs = {{0}};
    int statfs_ret = statfs(data_file, &path_fs);
    int fstatfs_ret = file_fd >= 0 ? fstatfs(file_fd, &fd_fs) : -1;
    printf("compat fd metadata fsync=%d ioctl=%d avail=%d statfs=%d bsize=%u fstatfs=%d fbsize=%u errno=%d\n",
        fsync_ret,
        ioctl_ret,
        meta_available,
        statfs_ret,
        (unsigned int)path_fs.f_bsize,
        fstatfs_ret,
        (unsigned int)fd_fs.f_bsize,
        errno);
    if (fsync_ret != 0 || ioctl_ret != 0 || meta_available != 2 || statfs_ret != 0 || path_fs.f_bsize == 0 || fstatfs_ret != 0 || fd_fs.f_bsize == 0) {{
        failures += 42;
    }}

    long raw_fd = compatra_syscall6(SYS_OPEN_NOCANCEL, (long)data_file, O_RDWR, 0600, 0, 0, 0);
    const char raw_text[] = "nc-ok";
    long raw_write = raw_fd >= 0 ? compatra_syscall6(SYS_WRITE_NOCANCEL, raw_fd, (long)raw_text, 5, 0, 0, 0) : -1;
    long raw_seek = raw_fd >= 0 ? (long)lseek((int)raw_fd, 0, SEEK_SET) : -1;
    char raw_buf[8] = {{0}};
    long raw_read = raw_fd >= 0 ? compatra_syscall6(SYS_READ_NOCANCEL, raw_fd, (long)raw_buf, 5, 0, 0, 0) : -1;
    long raw_fcntl = raw_fd >= 0 ? compatra_syscall6(SYS_FCNTL_NOCANCEL, raw_fd, F_GETFD, 0, 0, 0, 0) : -1;
    long raw_close = raw_fd >= 0 ? compatra_syscall6(SYS_CLOSE_NOCANCEL, raw_fd, 0, 0, 0, 0, 0) : -1;
    printf("compat fd nocancel io open=%ld write=%ld seek=%ld read=%ld errno=%d\n", raw_fd, raw_write, raw_seek, raw_read, errno);
    printf("compat fd nocancel result text=%s fcntl=%ld close=%ld errno=%d\n", raw_buf, raw_fcntl, raw_close, errno);
    if (raw_fd < 0 || raw_write != 5 || raw_seek != 0 || raw_read != 5 || !text_is(raw_buf, "nc-ok", 5) || raw_fcntl < 0 || raw_close != 0) {{
        failures += 45;
    }}

    int raw_pipe_fds[2] = {{-1, -1}};
    long raw_pipe = compatra_pipe_syscall(raw_pipe_fds);
    int raw_available = -1;
    if (raw_pipe == 0) {{
        write(raw_pipe_fds[1], "RP", 2);
    }}
    long raw_ioctl = raw_pipe == 0 ? compatra_syscall6(SYS_IOCTL, raw_pipe_fds[0], FIONREAD, (long)&raw_available, 0, 0, 0) : -1;
    char raw_pipe_buf[4] = {{0}};
    if (raw_pipe == 0) {{
        read(raw_pipe_fds[0], raw_pipe_buf, 2);
        close(raw_pipe_fds[0]);
        close(raw_pipe_fds[1]);
    }}
    long raw_fsync = file_fd >= 0 ? compatra_syscall6(SYS_FSYNC, file_fd, 0, 0, 0, 0, 0) : -1;
    struct statfs raw_path_fs = {{0}};
    struct statfs raw_fd_fs = {{0}};
    long raw_statfs = compatra_syscall6(SYS_STATFS64, (long)data_file, (long)&raw_path_fs, 0, 0, 0, 0);
    long raw_fstatfs = file_fd >= 0 ? compatra_syscall6(SYS_FSTATFS64, file_fd, (long)&raw_fd_fs, 0, 0, 0, 0) : -1;
    printf("compat fd raw syscalls pipe=%ld fds=%d,%d ioctl=%ld avail=%d text=%s fsync=%ld statfs=%ld bsize=%u fstatfs=%ld fbsize=%u errno=%d\n",
        raw_pipe,
        raw_pipe_fds[0],
        raw_pipe_fds[1],
        raw_ioctl,
        raw_available,
        raw_pipe_buf,
        raw_fsync,
        raw_statfs,
        (unsigned int)raw_path_fs.f_bsize,
        raw_fstatfs,
        (unsigned int)raw_fd_fs.f_bsize,
        errno);
    if (raw_pipe != 0 || raw_pipe_fds[0] < 0 || raw_pipe_fds[1] < 0 || raw_ioctl != 0 || raw_available != 2 || !text_is(raw_pipe_buf, "RP", 2) || raw_fsync != 0 || raw_statfs != 0 || raw_path_fs.f_bsize == 0 || raw_fstatfs != 0 || raw_fd_fs.f_bsize == 0) {{
        failures += 47;
    }}

    int dir_fd = open(data_dir, O_RDONLY);
    long raw_openat = dir_fd >= 0 ? compatra_syscall6(SYS_OPENAT, dir_fd, (long)"arm64_fd_compat.tmp", O_RDONLY, 0, 0, 0) : -1;
    long raw_faccessat = dir_fd >= 0 ? compatra_syscall6(SYS_FACCESSAT, dir_fd, (long)"arm64_fd_compat.tmp", R_OK, 0, 0, 0) : -1;
    struct stat raw_at_stat = {{0}};
    long raw_fstatat = dir_fd >= 0 ? compatra_syscall6(SYS_FSTATAT, dir_fd, (long)"arm64_fd_compat.tmp", (long)&raw_at_stat, 0, 0, 0) : -1;
    char raw_at_byte = 0;
    long raw_at_read = raw_openat >= 0 ? (long)read((int)raw_openat, &raw_at_byte, 1) : -1;
    if (raw_openat >= 0) {{
        close((int)raw_openat);
    }}
    if (dir_fd >= 0) {{
        close(dir_fd);
    }}
    printf("compat fd at syscalls dir=%d openat=%ld read=%ld byte=%c faccessat=%ld fstatat=%ld size=%lld errno=%d\n",
        dir_fd,
        raw_openat,
        raw_at_read,
        raw_at_byte,
        raw_faccessat,
        raw_fstatat,
        (long long)raw_at_stat.st_size,
        errno);
    if (dir_fd < 0 || raw_openat < 0 || raw_at_read != 1 || raw_faccessat != 0 || raw_fstatat != 0 || raw_at_stat.st_size <= 0) {{
        failures += 48;
    }}

    void *self = dlopen(NULL, RTLD_NOW);
    open_fn dyn_open = (open_fn)dlsym(self, "open");
    read_fn dyn_read = (read_fn)dlsym(self, "read");
    write_fn dyn_write = (write_fn)dlsym(self, "write");
    close_fn dyn_close = (close_fn)dlsym(self, "close");
    pipe_fn dyn_pipe = (pipe_fn)dlsym(self, "pipe");
    readv_fn dyn_readv = (readv_fn)dlsym(self, "readv");
    writev_fn dyn_writev = (writev_fn)dlsym(self, "writev");
    pread_fn dyn_pread = (pread_fn)dlsym(self, "pread");
    pwrite_fn dyn_pwrite = (pwrite_fn)dlsym(self, "pwrite");
    lseek_fn dyn_lseek = (lseek_fn)dlsym(self, "lseek");
    select_fn dyn_select = (select_fn)dlsym(self, "select");
    dup_fn dyn_dup = (dup_fn)dlsym(self, "dup");
    dup2_fn dyn_dup2 = (dup2_fn)dlsym(self, "dup2");
    printf("compat fd dlsym ptrs open=%p read=%p write=%p close=%p pipe=%p readv=%p writev=%p pread=%p pwrite=%p lseek=%p select=%p dup=%p dup2=%p\n", (void *)dyn_open, (void *)dyn_read, (void *)dyn_write, (void *)dyn_close, (void *)dyn_pipe, (void *)dyn_readv, (void *)dyn_writev, (void *)dyn_pread, (void *)dyn_pwrite, (void *)dyn_lseek, (void *)dyn_select, (void *)dyn_dup, (void *)dyn_dup2);
    if (!dyn_open || !dyn_read || !dyn_write || !dyn_close || !dyn_pipe || !dyn_readv || !dyn_writev || !dyn_pread || !dyn_pwrite || !dyn_lseek || !dyn_select || !dyn_dup || !dyn_dup2) {{
        return 50;
    }}
    failures += pipe_vec_roundtrip("dlsym", dyn_pipe, dyn_writev, dyn_readv);

    int dyn_rw_fd = dyn_open(data_file, O_CREAT | O_TRUNC | O_RDWR, 0600);
    long dyn_write_count = dyn_rw_fd >= 0 ? (long)dyn_write(dyn_rw_fd, "rw-ok", 5) : -1;
    long dyn_rw_seek = dyn_rw_fd >= 0 ? (long)dyn_lseek(dyn_rw_fd, 0, SEEK_SET) : -1;
    char dyn_rw_buf[8] = {{0}};
    long dyn_read_count = dyn_rw_fd >= 0 ? (long)dyn_read(dyn_rw_fd, dyn_rw_buf, 5) : -1;
    int dyn_close_ret = dyn_rw_fd >= 0 ? dyn_close(dyn_rw_fd) : -1;
    printf("compat fd dlsym rw io open=%d write=%ld seek=%ld read=%ld errno=%d\n", dyn_rw_fd, dyn_write_count, dyn_rw_seek, dyn_read_count, errno);
    printf("compat fd dlsym rw result text=%s close=%d errno=%d\n", dyn_rw_buf, dyn_close_ret, errno);
    if (dyn_rw_fd < 0 || dyn_write_count != 5 || dyn_rw_seek != 0 || dyn_read_count != 5 || !text_is(dyn_rw_buf, "rw-ok", 5) || dyn_close_ret != 0) {{
        failures += 55;
    }}

    long dyn_pwrite_count = (long)dyn_pwrite(file_fd, "dyn-ok", 6, 16);
    long dyn_seek_pos = (long)dyn_lseek(file_fd, 16, SEEK_SET);
    char dyn_positioned[16] = {{0}};
    long dyn_pread_count = (long)dyn_pread(file_fd, dyn_positioned, 6, 16);
    printf("compat fd dlsym positioned pwrite=%ld lseek=%ld pread=%ld text=%s errno=%d\n", dyn_pwrite_count, dyn_seek_pos, dyn_pread_count, dyn_positioned, errno);
    if (dyn_pwrite_count != 6 || dyn_seek_pos != 16 || dyn_pread_count != 6 || !text_is(dyn_positioned, "dyn-ok", 6)) {{
        failures += 60;
    }}

    close(file_fd);
    dlclose(self);
    return failures == 0 ? 0 : 1;
}}
"#
        ),
    )
    .expect("failed to write generated arm64 fd fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 fd fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 fd fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (binary, data_file)
}

#[cfg(target_os = "macos")]
fn compile_arm64_stdio_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_stdio_compat.c");
    let binary = out_dir.join("arm64_stdio_compat");
    let data_file = out_dir.join("arm64_stdio_compat.tmp");
    fs::write(
        &source,
        format!(
            r#"#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef FILE *(*fopen_fn)(const char *, const char *);
typedef FILE *(*fdopen_fn)(int, const char *);
typedef int (*fclose_fn)(FILE *);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef size_t (*fwrite_fn)(const void *, size_t, size_t, FILE *);
typedef int (*fflush_fn)(FILE *);
typedef int (*fseek_fn)(FILE *, long, int);
typedef long (*ftell_fn)(FILE *);
typedef char *(*fgets_fn)(char *, int, FILE *);
typedef int (*fputs_fn)(const char *, FILE *);
typedef int (*feof_fn)(FILE *);
typedef int (*ferror_fn)(FILE *);
typedef void (*clearerr_fn)(FILE *);
typedef int (*fileno_fn)(FILE *);

static int text_is(const char *text, const char *expected) {{
    while (*text && *expected && *text == *expected) {{
        text++;
        expected++;
    }}
    return *text == 0 && *expected == 0;
}}

static void strip_newline(char *text) {{
    for (unsigned long i = 0; text[i] != 0; i++) {{
        if (text[i] == '\n') {{
            text[i] = 0;
            return;
        }}
    }}
}}

static void fixture_dir_from_argv0(const char *argv0, char *out, size_t out_len) {{
    if (out_len == 0) {{
        return;
    }}
    (void)argv0;
    snprintf(out, out_len, ".");
}}

static void join_path(const char *base, const char *name, char *out, size_t out_len) {{
    if (strcmp(base, "/") == 0) {{
        snprintf(out, out_len, "/%s", name);
    }} else {{
        snprintf(out, out_len, "%s/%s", base, name);
    }}
}}

static void fixture_path_from_argv0(const char *argv0, const char *name, char *out, size_t out_len) {{
    char dir[4096] = {{0}};
    fixture_dir_from_argv0(argv0, dir, sizeof(dir));
    join_path(dir, name, out, out_len);
}}

static void fixture_dir_from_optional_arg(int argc, char **argv, const char *argv0, char *out, size_t out_len) {{
    if (argc > 1 && argv && argv[1] && argv[1][0]) {{
        snprintf(out, out_len, "%s", argv[1]);
    }} else {{
        fixture_dir_from_argv0(argv0, out, out_len);
    }}
}}

static int stdio_roundtrip(
    const char *label,
    const char *data_file,
    fopen_fn fopen_impl,
    fdopen_fn fdopen_impl,
    fclose_fn fclose_impl,
    fread_fn fread_impl,
    fwrite_fn fwrite_impl,
    fflush_fn fflush_impl,
    fseek_fn fseek_impl,
    ftell_fn ftell_impl,
    fgets_fn fgets_impl,
    fputs_fn fputs_impl,
    feof_fn feof_impl,
    ferror_fn ferror_impl,
    clearerr_fn clearerr_impl,
    fileno_fn fileno_impl
) {{
    FILE *stream = fopen_impl(data_file, "w+");
    const char payload[] = "stdio-one\nstdio-two\n";
    size_t wrote = stream ? fwrite_impl(payload, 1, sizeof(payload) - 1, stream) : 0;
    int puts_ret = stream ? fputs_impl("tail\n", stream) : -1;
    int flush_ret = stream ? fflush_impl(stream) : -1;
    long pos_after_write = stream ? ftell_impl(stream) : -1;
    int fd = stream ? fileno_impl(stream) : -1;
    int seek_ret = stream ? fseek_impl(stream, 0, SEEK_SET) : -1;

    char line[32] = {{0}};
    char second[32] = {{0}};
    char tail[16] = {{0}};
    char eof_byte = 0;
    char *line_ret = stream ? fgets_impl(line, sizeof(line), stream) : 0;
    if (line_ret) {{
        strip_newline(line);
    }}
    size_t second_read = stream ? fread_impl(second, 1, 10, stream) : 0;
    if (second_read < sizeof(second)) {{
        second[second_read] = 0;
    }}
    strip_newline(second);
    int tail_seek = stream ? fseek_impl(stream, -5, SEEK_END) : -1;
    size_t tail_read = stream ? fread_impl(tail, 1, 5, stream) : 0;
    if (tail_read < sizeof(tail)) {{
        tail[tail_read] = 0;
    }}
    strip_newline(tail);
    size_t eof_read = stream ? fread_impl(&eof_byte, 1, 1, stream) : 0;
    int eof_state = stream ? feof_impl(stream) : 0;
    int error_state = stream ? ferror_impl(stream) : -1;
    if (stream) {{
        clearerr_impl(stream);
    }}
    int eof_after_clear = stream ? feof_impl(stream) : -1;
    int close_ret = stream ? fclose_impl(stream) : -1;
    printf(
        "compat stdio %s open=%p fwrite=%lu fputs=%d flush=%d pos=%ld fd=%d seek=%d line=%s read=%lu text=%s tail_seek=%d tail=%s eof_read=%lu eof=%d err=%d eof_after=%d close=%d errno=%d\n",
        label,
        (void *)stream,
        (unsigned long)wrote,
        puts_ret,
        flush_ret,
        pos_after_write,
        fd,
        seek_ret,
        line,
        (unsigned long)second_read,
        second,
        tail_seek,
        tail,
        (unsigned long)eof_read,
        eof_state,
        error_state,
        eof_after_clear,
        close_ret,
        errno
    );

    int raw_fd = open(data_file, O_RDONLY);
    FILE *fd_stream = raw_fd >= 0 ? fdopen_impl(raw_fd, "r") : 0;
    char fd_buf[16] = {{0}};
    size_t fd_read = fd_stream ? fread_impl(fd_buf, 1, 5, fd_stream) : 0;
    if (fd_read < sizeof(fd_buf)) {{
        fd_buf[fd_read] = 0;
    }}
    int fd_close = fd_stream ? fclose_impl(fd_stream) : -1;
    if (!fd_stream && raw_fd >= 0) {{
        close(raw_fd);
    }}
    printf("compat stdio %s fdopen fd=%d stream=%p read=%lu text=%s close=%d errno=%d\n", label, raw_fd, (void *)fd_stream, (unsigned long)fd_read, fd_buf, fd_close, errno);

    if (!stream || wrote != sizeof(payload) - 1 || puts_ret < 0 || flush_ret != 0 || pos_after_write < 25 || fd < 0 || seek_ret != 0 || !line_ret || !text_is(line, "stdio-one") || second_read != 10 || !text_is(second, "stdio-two") || tail_seek != 0 || tail_read != 5 || !text_is(tail, "tail") || eof_read != 0 || eof_state == 0 || error_state != 0 || eof_after_clear != 0 || close_ret != 0) {{
        return 1;
    }}
    if (!fd_stream || fd_read != 5 || !text_is(fd_buf, "stdio") || fd_close != 0) {{
        return 2;
    }}
    return 0;
}}

int main(int argc, char **argv) {{
    int failures = 0;
    const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : ".";
    char data_dir[4096] = {{0}};
    char data_file[4096] = {{0}};
    fixture_dir_from_optional_arg(argc, argv, argv0, data_dir, sizeof(data_dir));
    join_path(data_dir, "arm64_stdio_compat.tmp", data_file, sizeof(data_file));
    printf(
        "compat stdio paths argc=%d argv1=%s data_dir=%s data_file=%s\n",
        argc,
        (argc > 1 && argv && argv[1]) ? argv[1] : "<none>",
        data_dir,
        data_file
    );
    failures += stdio_roundtrip("static", data_file, fopen, fdopen, fclose, fread, fwrite, fflush, fseek, ftell, fgets, fputs, feof, ferror, clearerr, fileno);

    void *self = dlopen(NULL, RTLD_NOW);
    fopen_fn dyn_fopen = (fopen_fn)dlsym(self, "fopen");
    fdopen_fn dyn_fdopen = (fdopen_fn)dlsym(self, "fdopen");
    fclose_fn dyn_fclose = (fclose_fn)dlsym(self, "fclose");
    fread_fn dyn_fread = (fread_fn)dlsym(self, "fread");
    fwrite_fn dyn_fwrite = (fwrite_fn)dlsym(self, "fwrite");
    fflush_fn dyn_fflush = (fflush_fn)dlsym(self, "fflush");
    fseek_fn dyn_fseek = (fseek_fn)dlsym(self, "fseek");
    ftell_fn dyn_ftell = (ftell_fn)dlsym(self, "ftell");
    fgets_fn dyn_fgets = (fgets_fn)dlsym(self, "fgets");
    fputs_fn dyn_fputs = (fputs_fn)dlsym(self, "fputs");
    feof_fn dyn_feof = (feof_fn)dlsym(self, "feof");
    ferror_fn dyn_ferror = (ferror_fn)dlsym(self, "ferror");
    clearerr_fn dyn_clearerr = (clearerr_fn)dlsym(self, "clearerr");
    fileno_fn dyn_fileno = (fileno_fn)dlsym(self, "fileno");
    printf(
        "compat stdio dlsym ptrs fopen=%p fdopen=%p fread=%p fwrite=%p fseek=%p fgets=%p clearerr=%p fileno=%p\n",
        (void *)dyn_fopen,
        (void *)dyn_fdopen,
        (void *)dyn_fread,
        (void *)dyn_fwrite,
        (void *)dyn_fseek,
        (void *)dyn_fgets,
        (void *)dyn_clearerr,
        (void *)dyn_fileno
    );
    if (!dyn_fopen || !dyn_fdopen || !dyn_fclose || !dyn_fread || !dyn_fwrite || !dyn_fflush || !dyn_fseek || !dyn_ftell || !dyn_fgets || !dyn_fputs || !dyn_feof || !dyn_ferror || !dyn_clearerr || !dyn_fileno) {{
        return 3;
    }}
    failures += stdio_roundtrip("dlsym", data_file, dyn_fopen, dyn_fdopen, dyn_fclose, dyn_fread, dyn_fwrite, dyn_fflush, dyn_fseek, dyn_ftell, dyn_fgets, dyn_fputs, dyn_feof, dyn_ferror, dyn_clearerr, dyn_fileno);
    dlclose(self);
    unlink(data_file);
    return failures == 0 ? 0 : 1;
}}
"#
        ),
    )
    .expect("failed to write generated arm64 stdio fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 stdio fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 stdio fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (binary, data_file)
}

#[cfg(target_os = "macos")]
fn compile_arm64_path_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_path_compat.c");
    let binary = out_dir.join("arm64_path_compat");
    let base_dir = out_dir.join("path-host-root");
    fs::write(
        &source,
        format!(
            r#"#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SYS_CHMOD 0x200000F
#define SYS_FCHMOD 0x200007C
#define SYS_TRUNCATE 0x20000C8
#define SYS_FTRUNCATE 0x20000C9
#define SYS_RENAMEAT 0x20001D1
#define SYS_FCHMODAT 0x20001D3
#define SYS_UNLINKAT 0x20001D8
#define SYS_READLINKAT 0x20001D9
#define SYS_MKDIRAT 0x20001DB

typedef int (*access_fn)(const char *, int);
typedef int (*chmod_fn)(const char *, mode_t);
typedef int (*fchmod_fn)(int, mode_t);
typedef int (*fchmodat_fn)(int, const char *, mode_t, int);
typedef int (*chdir_fn)(const char *);
typedef char *(*getcwd_fn)(char *, size_t);
typedef int (*stat_fn)(const char *, struct stat *);
typedef int (*lstat_fn)(const char *, struct stat *);
typedef int (*fstat_fn)(int, struct stat *);
typedef int (*truncate_fn)(const char *, off_t);
typedef int (*ftruncate_fn)(int, off_t);
typedef int (*mkdir_fn)(const char *, mode_t);
typedef int (*mkdirat_fn)(int, const char *, mode_t);
typedef int (*rmdir_fn)(const char *);
typedef int (*unlink_fn)(const char *);
typedef int (*unlinkat_fn)(int, const char *, int);
typedef int (*rename_fn)(const char *, const char *);
typedef int (*renameat_fn)(int, const char *, int, const char *);
typedef ssize_t (*readlink_fn)(const char *, char *, size_t);
typedef ssize_t (*readlinkat_fn)(int, const char *, char *, size_t);
typedef int (*symlink_fn)(const char *, const char *);
typedef char *(*realpath_fn)(const char *, char *);
typedef ssize_t (*getxattr_fn)(const char *, const char *, void *, size_t, uint32_t, int);
typedef ssize_t (*fgetxattr_fn)(int, const char *, void *, size_t, uint32_t, int);
typedef int (*setxattr_fn)(const char *, const char *, const void *, size_t, uint32_t, int);
typedef int (*fsetxattr_fn)(int, const char *, const void *, size_t, uint32_t, int);
typedef ssize_t (*listxattr_fn)(const char *, char *, size_t, int);
typedef ssize_t (*flistxattr_fn)(int, char *, size_t, int);
typedef int (*removexattr_fn)(const char *, const char *, int);
typedef int (*fremovexattr_fn)(int, const char *, int);

extern char *realpath(const char *, char *);

static long compatra_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    asm volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
        : "memory", "cc");
    return x0;
}}

static int text_is(const char *text, const char *expected) {{
    return strcmp(text, expected) == 0;
}}

static int xattr_list_has_name(const char *list, ssize_t len, const char *name) {{
    ssize_t offset = 0;
    while (offset < len) {{
        const char *entry = list + offset;
        size_t entry_len = strlen(entry);
        if (entry_len == 0) {{
            break;
        }}
        if (strcmp(entry, name) == 0) {{
            return 1;
        }}
        offset += (ssize_t)entry_len + 1;
    }}
    return 0;
}}

static void fixture_dir_from_argv0(const char *argv0, char *out, size_t out_len) {{
    if (out_len == 0) {{
        return;
    }}
    (void)argv0;
    snprintf(out, out_len, ".");
}}

static void join_path(const char *base, const char *name, char *out, size_t out_len) {{
    if (strcmp(base, "/") == 0) {{
        snprintf(out, out_len, "/%s", name);
    }} else {{
        snprintf(out, out_len, "%s/%s", base, name);
    }}
}}

static void fixture_dir_from_optional_arg(int argc, char **argv, const char *argv0, char *out, size_t out_len) {{
    if (argc > 1 && argv && argv[1] && argv[1][0]) {{
        snprintf(out, out_len, "%s", argv[1]);
    }} else {{
        fixture_dir_from_argv0(argv0, out, out_len);
    }}
}}

static void unlink_child(const char *base, const char *name) {{
    char path[4096] = {{0}};
    join_path(base, name, path, sizeof(path));
    unlink(path);
}}

static void rmdir_child(const char *base, const char *name) {{
    char path[4096] = {{0}};
    join_path(base, name, path, sizeof(path));
    rmdir(path);
}}

static void cleanup_base(const char *base_dir) {{
    unlink_child(base_dir, "alpha.txt");
    unlink_child(base_dir, "beta.txt");
    unlink_child(base_dir, "alpha.link");
    unlink_child(base_dir, "raw-at.txt");
    unlink_child(base_dir, "raw-new.txt");
    unlink_child(base_dir, "raw.link");
    unlink_child(base_dir, "dyn-old.txt");
    unlink_child(base_dir, "dyn-new.txt");
    unlink_child(base_dir, "dyn.link");
    unlink_child(base_dir, "dyn-mode.txt");
    unlink_child(base_dir, "dyn-at.txt");
    unlink_child(base_dir, "dyn-at-new.txt");
    unlink_child(base_dir, "dyn-at.link");
    rmdir_child(base_dir, "raw-dir");
    rmdir_child(base_dir, "dyn-dir");
    rmdir_child(base_dir, "dyn-at-dir");
    rmdir_child(base_dir, "empty");
    rmdir(base_dir);
}}

int main(int argc, char **argv) {{
    int failures = 0;
    const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : ".";
    char fixture_dir[4096] = {{0}};
    char base_dir[4096] = {{0}};
    fixture_dir_from_optional_arg(argc, argv, argv0, fixture_dir, sizeof(fixture_dir));
    join_path(fixture_dir, "path-host-root", base_dir, sizeof(base_dir));
    printf(
        "compat path base argc=%d argv1=%s fixture_dir=%s base=%s\n",
        argc,
        (argc > 1 && argv && argv[1]) ? argv[1] : "<none>",
        fixture_dir,
        base_dir
    );
    cleanup_base(base_dir);
    int mkdir_base = mkdir(base_dir, 0700);
    int chdir_base = chdir(base_dir);
    char cwd[4096] = {{0}};
    char *cwd_ret = getcwd(cwd, sizeof(cwd));
    printf("compat path cwd mkdir=%d chdir=%d ret=%p cwd=%s errno=%d\n", mkdir_base, chdir_base, (void *)cwd_ret, cwd, errno);
    if (mkdir_base != 0 || chdir_base != 0 || cwd_ret == 0 || strstr(cwd, "path-host-root") == 0) {{
        failures += 10;
    }}

    int fd = open("alpha.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    write(fd, "hello", 5);
    int chmod_ret = chmod("alpha.txt", 0644);
    int fchmod_ret = fchmod(fd, 0600);
    int truncate_ret = truncate("alpha.txt", 4);
    int ftruncate_ret = ftruncate(fd, 5);
    struct stat st = {{0}};
    struct stat lst = {{0}};
    struct stat fst = {{0}};
    int access_ret = access("alpha.txt", R_OK | W_OK);
    int stat_ret = stat("alpha.txt", &st);
    int fstat_ret = fstat(fd, &fst);
    int symlink_ret = symlink("alpha.txt", "alpha.link");
    char link_target[128] = {{0}};
    long readlink_ret = (long)readlink("alpha.link", link_target, sizeof(link_target) - 1);
    if (readlink_ret >= 0 && readlink_ret < (long)sizeof(link_target)) {{
        link_target[readlink_ret] = 0;
    }}
    int lstat_ret = lstat("alpha.link", &lst);
    char resolved[4096] = {{0}};
    char *realpath_ret = realpath("alpha.txt", resolved);
    const char *xattr_name = "com.compatra.test";
    const char *xattr_value = "xattr-ok";
    char xattr_buf[64] = {{0}};
    char xattr_list[256] = {{0}};
    int xattr_set = setxattr("alpha.txt", xattr_name, xattr_value, strlen(xattr_value), 0, 0);
    ssize_t xattr_get = getxattr("alpha.txt", xattr_name, xattr_buf, sizeof(xattr_buf) - 1, 0, 0);
    if (xattr_get >= 0 && xattr_get < (ssize_t)sizeof(xattr_buf)) {{
        xattr_buf[xattr_get] = 0;
    }}
    ssize_t xattr_list_ret = listxattr("alpha.txt", xattr_list, sizeof(xattr_list), 0);
    int xattr_has = xattr_list_has_name(xattr_list, xattr_list_ret, xattr_name);
    int xattr_remove = removexattr("alpha.txt", xattr_name, 0);
    printf(
        "compat path static access=%d stat=%d size=%lld fstat=%d size=%lld symlink=%d readlink=%ld target=%s lstat=%d linksize=%lld realpath=%p resolved=%s errno=%d\n",
        access_ret,
        stat_ret,
        (long long)st.st_size,
        fstat_ret,
        (long long)fst.st_size,
        symlink_ret,
        readlink_ret,
        link_target,
        lstat_ret,
        (long long)lst.st_size,
        (void *)realpath_ret,
        resolved,
        errno
    );
    printf("compat path static stat access=%d stat=%d fstat=%d lstat=%d errno=%d\n", access_ret, stat_ret, fstat_ret, lstat_ret, errno);
    printf("compat path static mode chmod=%d fchmod=%d truncate=%d ftruncate=%d errno=%d\n", chmod_ret, fchmod_ret, truncate_ret, ftruncate_ret, errno);
    printf("compat path static sizes stat=%lld fstat=%lld link=%lld\n", (long long)st.st_size, (long long)fst.st_size, (long long)lst.st_size);
    printf("compat path static link symlink=%d readlink=%ld target=%s realpath=%p errno=%d\n", symlink_ret, readlink_ret, link_target, (void *)realpath_ret, errno);
    printf("compat path static xattr set=%d get=%ld text=%s list=%ld has=%d remove=%d errno=%d\n", xattr_set, (long)xattr_get, xattr_buf, (long)xattr_list_ret, xattr_has, xattr_remove, errno);
    if (fd < 0 || chmod_ret != 0 || fchmod_ret != 0 || truncate_ret != 0 || ftruncate_ret != 0 || access_ret != 0 || stat_ret != 0 || st.st_size != 5 || fstat_ret != 0 || fst.st_size != 5 || symlink_ret != 0 || readlink_ret != 9 || !text_is(link_target, "alpha.txt") || lstat_ret != 0 || realpath_ret == 0) {{
        failures += 20;
    }}
    if (xattr_set != 0 || xattr_get != (ssize_t)strlen(xattr_value) || !text_is(xattr_buf, xattr_value) || xattr_list_ret <= 0 || !xattr_has || xattr_remove != 0) {{
        failures += 25;
    }}
    close(fd);

    int rename_ret = rename("alpha.txt", "beta.txt");
    int unlink_ret = unlink("beta.txt");
    int unlink_link_ret = unlink("alpha.link");
    int mkdir_empty = mkdir("empty", 0700);
    int rmdir_empty = rmdir("empty");
    printf("compat path static mutate rename=%d unlink=%d unlink_link=%d mkdir=%d rmdir=%d errno=%d\n", rename_ret, unlink_ret, unlink_link_ret, mkdir_empty, rmdir_empty, errno);
    if (rename_ret != 0 || unlink_ret != 0 || unlink_link_ret != 0 || mkdir_empty != 0 || rmdir_empty != 0) {{
        failures += 30;
    }}

    int raw_fd = open("raw-at.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    write(raw_fd, "rawbuf", 6);
    long raw_chmod = compatra_syscall6(SYS_CHMOD, (long)"raw-at.txt", 0644, 0, 0, 0, 0);
    long raw_fchmod = compatra_syscall6(SYS_FCHMOD, raw_fd, 0600, 0, 0, 0, 0);
    long raw_fchmodat = compatra_syscall6(SYS_FCHMODAT, AT_FDCWD, (long)"raw-at.txt", 0644, 0, 0, 0);
    long raw_truncate = compatra_syscall6(SYS_TRUNCATE, (long)"raw-at.txt", 3, 0, 0, 0, 0);
    long raw_ftruncate = compatra_syscall6(SYS_FTRUNCATE, raw_fd, 4, 0, 0, 0, 0);
    struct stat raw_st = {{0}};
    stat("raw-at.txt", &raw_st);
    long raw_mkdirat = compatra_syscall6(SYS_MKDIRAT, AT_FDCWD, (long)"raw-dir", 0700, 0, 0, 0);
    long raw_renameat = compatra_syscall6(SYS_RENAMEAT, AT_FDCWD, (long)"raw-at.txt", AT_FDCWD, (long)"raw-new.txt", 0, 0);
    int raw_symlink = symlink("raw-new.txt", "raw.link");
    char raw_link_target[128] = {{0}};
    long raw_readlinkat = compatra_syscall6(SYS_READLINKAT, AT_FDCWD, (long)"raw.link", (long)raw_link_target, sizeof(raw_link_target) - 1, 0, 0);
    if (raw_readlinkat >= 0 && raw_readlinkat < (long)sizeof(raw_link_target)) {{
        raw_link_target[raw_readlinkat] = 0;
    }}
    long raw_unlinkat = compatra_syscall6(SYS_UNLINKAT, AT_FDCWD, (long)"raw-new.txt", 0, 0, 0, 0);
    long raw_unlinkat_link = compatra_syscall6(SYS_UNLINKAT, AT_FDCWD, (long)"raw.link", 0, 0, 0, 0);
    int raw_rmdir = rmdir("raw-dir");
    close(raw_fd);
    printf("compat path raw syscall mode chmod=%ld fchmod=%ld fchmodat=%ld truncate=%ld ftruncate=%ld size=%lld errno=%d\n", raw_chmod, raw_fchmod, raw_fchmodat, raw_truncate, raw_ftruncate, (long long)raw_st.st_size, errno);
    printf("compat path raw at mkdirat=%ld renameat=%ld symlink=%d readlinkat=%ld target=%s unlinkat=%ld unlink_link=%ld rmdir=%d errno=%d\n", raw_mkdirat, raw_renameat, raw_symlink, raw_readlinkat, raw_link_target, raw_unlinkat, raw_unlinkat_link, raw_rmdir, errno);
    if (raw_fd < 0 || raw_chmod != 0 || raw_fchmod != 0 || raw_fchmodat != 0 || raw_truncate != 0 || raw_ftruncate != 0 || raw_st.st_size != 4 || raw_mkdirat != 0 || raw_renameat != 0 || raw_symlink != 0 || raw_readlinkat != 11 || !text_is(raw_link_target, "raw-new.txt") || raw_unlinkat != 0 || raw_unlinkat_link != 0 || raw_rmdir != 0) {{
        failures += 35;
    }}

    void *self = dlopen(NULL, RTLD_NOW);
    access_fn dyn_access = (access_fn)dlsym(self, "access");
    chmod_fn dyn_chmod = (chmod_fn)dlsym(self, "chmod");
    fchmod_fn dyn_fchmod = (fchmod_fn)dlsym(self, "fchmod");
    fchmodat_fn dyn_fchmodat = (fchmodat_fn)dlsym(self, "fchmodat");
    chdir_fn dyn_chdir = (chdir_fn)dlsym(self, "chdir");
    getcwd_fn dyn_getcwd = (getcwd_fn)dlsym(self, "getcwd");
    stat_fn dyn_stat = (stat_fn)dlsym(self, "stat");
    lstat_fn dyn_lstat = (lstat_fn)dlsym(self, "lstat");
    fstat_fn dyn_fstat = (fstat_fn)dlsym(self, "fstat");
    truncate_fn dyn_truncate = (truncate_fn)dlsym(self, "truncate");
    ftruncate_fn dyn_ftruncate = (ftruncate_fn)dlsym(self, "ftruncate");
    mkdir_fn dyn_mkdir = (mkdir_fn)dlsym(self, "mkdir");
    mkdirat_fn dyn_mkdirat = (mkdirat_fn)dlsym(self, "mkdirat");
    rmdir_fn dyn_rmdir = (rmdir_fn)dlsym(self, "rmdir");
    unlink_fn dyn_unlink = (unlink_fn)dlsym(self, "unlink");
    unlinkat_fn dyn_unlinkat = (unlinkat_fn)dlsym(self, "unlinkat");
    rename_fn dyn_rename = (rename_fn)dlsym(self, "rename");
    renameat_fn dyn_renameat = (renameat_fn)dlsym(self, "renameat");
    readlink_fn dyn_readlink = (readlink_fn)dlsym(self, "readlink");
    readlinkat_fn dyn_readlinkat = (readlinkat_fn)dlsym(self, "readlinkat");
    symlink_fn dyn_symlink = (symlink_fn)dlsym(self, "symlink");
    realpath_fn dyn_realpath = (realpath_fn)dlsym(self, "realpath");
    getxattr_fn dyn_getxattr = (getxattr_fn)dlsym(self, "getxattr");
    fgetxattr_fn dyn_fgetxattr = (fgetxattr_fn)dlsym(self, "fgetxattr");
    setxattr_fn dyn_setxattr = (setxattr_fn)dlsym(self, "setxattr");
    fsetxattr_fn dyn_fsetxattr = (fsetxattr_fn)dlsym(self, "fsetxattr");
    listxattr_fn dyn_listxattr = (listxattr_fn)dlsym(self, "listxattr");
    flistxattr_fn dyn_flistxattr = (flistxattr_fn)dlsym(self, "flistxattr");
    removexattr_fn dyn_removexattr = (removexattr_fn)dlsym(self, "removexattr");
    fremovexattr_fn dyn_fremovexattr = (fremovexattr_fn)dlsym(self, "fremovexattr");
    printf(
        "compat path dlsym ptrs %p %p %p %p %p %p %p %p %p %p %p %p %p\n",
        (void *)dyn_access,
        (void *)dyn_chdir,
        (void *)dyn_getcwd,
        (void *)dyn_stat,
        (void *)dyn_lstat,
        (void *)dyn_fstat,
        (void *)dyn_mkdir,
        (void *)dyn_rmdir,
        (void *)dyn_unlink,
        (void *)dyn_rename,
        (void *)dyn_readlink,
        (void *)dyn_symlink,
        (void *)dyn_realpath
    );
    printf(
        "compat path dlsym at ptrs chmod=%p fchmod=%p fchmodat=%p truncate=%p ftruncate=%p mkdirat=%p unlinkat=%p renameat=%p readlinkat=%p\n",
        (void *)dyn_chmod,
        (void *)dyn_fchmod,
        (void *)dyn_fchmodat,
        (void *)dyn_truncate,
        (void *)dyn_ftruncate,
        (void *)dyn_mkdirat,
        (void *)dyn_unlinkat,
        (void *)dyn_renameat,
        (void *)dyn_readlinkat
    );
    printf(
        "compat path dlsym xattr ptrs get=%p fget=%p set=%p fset=%p list=%p flist=%p remove=%p fremove=%p\n",
        (void *)dyn_getxattr,
        (void *)dyn_fgetxattr,
        (void *)dyn_setxattr,
        (void *)dyn_fsetxattr,
        (void *)dyn_listxattr,
        (void *)dyn_flistxattr,
        (void *)dyn_removexattr,
        (void *)dyn_fremovexattr
    );
    if (!dyn_access || !dyn_chmod || !dyn_fchmod || !dyn_fchmodat || !dyn_chdir || !dyn_getcwd || !dyn_stat || !dyn_lstat || !dyn_fstat || !dyn_truncate || !dyn_ftruncate || !dyn_mkdir || !dyn_mkdirat || !dyn_rmdir || !dyn_unlink || !dyn_unlinkat || !dyn_rename || !dyn_renameat || !dyn_readlink || !dyn_readlinkat || !dyn_symlink || !dyn_realpath || !dyn_getxattr || !dyn_fgetxattr || !dyn_setxattr || !dyn_fsetxattr || !dyn_listxattr || !dyn_flistxattr || !dyn_removexattr || !dyn_fremovexattr) {{
        return 40;
    }}

    int dyn_mkdir_dir = dyn_mkdir("dyn-dir", 0700);
    int dyn_chdir_dir = dyn_chdir("dyn-dir");
    char dyn_cwd[4096] = {{0}};
    char *dyn_cwd_ret = dyn_getcwd(dyn_cwd, sizeof(dyn_cwd));
    int dyn_chdir_back = dyn_chdir("..");
    printf("compat path dlsym cwd mkdir=%d chdir=%d ret=%p cwd=%s back=%d errno=%d\n", dyn_mkdir_dir, dyn_chdir_dir, (void *)dyn_cwd_ret, dyn_cwd, dyn_chdir_back, errno);
    if (dyn_mkdir_dir != 0 || dyn_chdir_dir != 0 || dyn_cwd_ret == 0 || strstr(dyn_cwd, "dyn-dir") == 0 || dyn_chdir_back != 0) {{
        failures += 50;
    }}

    int dyn_fd = open("dyn-old.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    write(dyn_fd, "dynamic", 7);
    struct stat dyn_st = {{0}};
    struct stat dyn_fst = {{0}};
    int dyn_rename_ret = dyn_rename("dyn-old.txt", "dyn-new.txt");
    int dyn_access_ret = dyn_access("dyn-new.txt", R_OK);
    int dyn_stat_ret = dyn_stat("dyn-new.txt", &dyn_st);
    int dyn_fstat_ret = dyn_fstat(dyn_fd, &dyn_fst);
    int dyn_symlink_ret = dyn_symlink("dyn-new.txt", "dyn.link");
    char dyn_link_target[128] = {{0}};
    long dyn_readlink_ret = (long)dyn_readlink("dyn.link", dyn_link_target, sizeof(dyn_link_target) - 1);
    if (dyn_readlink_ret >= 0 && dyn_readlink_ret < (long)sizeof(dyn_link_target)) {{
        dyn_link_target[dyn_readlink_ret] = 0;
    }}
    struct stat dyn_lst = {{0}};
    int dyn_lstat_ret = dyn_lstat("dyn.link", &dyn_lst);
    char dyn_resolved[4096] = {{0}};
    char *dyn_realpath_ret = dyn_realpath("dyn-new.txt", dyn_resolved);
    const char *dyn_xattr_name = "com.compatra.dynamic";
    const char *dyn_xattr_value = "dyn-xattr-ok";
    const char *dyn_fxattr_name = "com.compatra.fd";
    const char *dyn_fxattr_value = "fd-xattr-ok";
    char dyn_xattr_buf[64] = {{0}};
    char dyn_fxattr_buf[64] = {{0}};
    char dyn_xattr_list[256] = {{0}};
    char dyn_fxattr_list[256] = {{0}};
    int dyn_xattr_set = dyn_setxattr("dyn-new.txt", dyn_xattr_name, dyn_xattr_value, strlen(dyn_xattr_value), 0, 0);
    ssize_t dyn_xattr_get = dyn_getxattr("dyn-new.txt", dyn_xattr_name, dyn_xattr_buf, sizeof(dyn_xattr_buf) - 1, 0, 0);
    if (dyn_xattr_get >= 0 && dyn_xattr_get < (ssize_t)sizeof(dyn_xattr_buf)) {{
        dyn_xattr_buf[dyn_xattr_get] = 0;
    }}
    ssize_t dyn_xattr_list_ret = dyn_listxattr("dyn-new.txt", dyn_xattr_list, sizeof(dyn_xattr_list), 0);
    int dyn_xattr_has = xattr_list_has_name(dyn_xattr_list, dyn_xattr_list_ret, dyn_xattr_name);
    int dyn_fxattr_set = dyn_fsetxattr(dyn_fd, dyn_fxattr_name, dyn_fxattr_value, strlen(dyn_fxattr_value), 0, 0);
    ssize_t dyn_fxattr_get = dyn_fgetxattr(dyn_fd, dyn_fxattr_name, dyn_fxattr_buf, sizeof(dyn_fxattr_buf) - 1, 0, 0);
    if (dyn_fxattr_get >= 0 && dyn_fxattr_get < (ssize_t)sizeof(dyn_fxattr_buf)) {{
        dyn_fxattr_buf[dyn_fxattr_get] = 0;
    }}
    ssize_t dyn_fxattr_list_ret = dyn_flistxattr(dyn_fd, dyn_fxattr_list, sizeof(dyn_fxattr_list), 0);
    int dyn_fxattr_has = xattr_list_has_name(dyn_fxattr_list, dyn_fxattr_list_ret, dyn_fxattr_name);
    int dyn_fxattr_remove = dyn_fremovexattr(dyn_fd, dyn_fxattr_name, 0);
    int dyn_xattr_remove = dyn_removexattr("dyn-new.txt", dyn_xattr_name, 0);
    printf(
        "compat path dlsym file rename=%d access=%d stat=%d size=%lld fstat=%d size=%lld symlink=%d readlink=%ld target=%s lstat=%d realpath=%p resolved=%s errno=%d\n",
        dyn_rename_ret,
        dyn_access_ret,
        dyn_stat_ret,
        (long long)dyn_st.st_size,
        dyn_fstat_ret,
        (long long)dyn_fst.st_size,
        dyn_symlink_ret,
        dyn_readlink_ret,
        dyn_link_target,
        dyn_lstat_ret,
        (void *)dyn_realpath_ret,
        dyn_resolved,
        errno
    );
    printf("compat path dlsym stat rename=%d access=%d stat=%d fstat=%d lstat=%d errno=%d\n", dyn_rename_ret, dyn_access_ret, dyn_stat_ret, dyn_fstat_ret, dyn_lstat_ret, errno);
    printf("compat path dlsym sizes stat=%lld fstat=%lld\n", (long long)dyn_st.st_size, (long long)dyn_fst.st_size);
    printf("compat path dlsym link symlink=%d readlink=%ld target=%s realpath=%p errno=%d\n", dyn_symlink_ret, dyn_readlink_ret, dyn_link_target, (void *)dyn_realpath_ret, errno);
    printf("compat path dlsym xattr set=%d get=%ld text=%s list=%ld has=%d remove=%d fset=%d fget=%ld ftext=%s flist=%ld fhas=%d fremove=%d errno=%d\n",
        dyn_xattr_set,
        (long)dyn_xattr_get,
        dyn_xattr_buf,
        (long)dyn_xattr_list_ret,
        dyn_xattr_has,
        dyn_xattr_remove,
        dyn_fxattr_set,
        (long)dyn_fxattr_get,
        dyn_fxattr_buf,
        (long)dyn_fxattr_list_ret,
        dyn_fxattr_has,
        dyn_fxattr_remove,
        errno
    );
    if (dyn_fd < 0 || dyn_rename_ret != 0 || dyn_access_ret != 0 || dyn_stat_ret != 0 || dyn_st.st_size != 7 || dyn_fstat_ret != 0 || dyn_fst.st_size != 7 || dyn_symlink_ret != 0 || dyn_readlink_ret != 11 || !text_is(dyn_link_target, "dyn-new.txt") || dyn_lstat_ret != 0 || dyn_realpath_ret == 0) {{
        failures += 60;
    }}
    if (dyn_xattr_set != 0 || dyn_xattr_get != (ssize_t)strlen(dyn_xattr_value) || !text_is(dyn_xattr_buf, dyn_xattr_value) || dyn_xattr_list_ret <= 0 || !dyn_xattr_has || dyn_xattr_remove != 0 || dyn_fxattr_set != 0 || dyn_fxattr_get != (ssize_t)strlen(dyn_fxattr_value) || !text_is(dyn_fxattr_buf, dyn_fxattr_value) || dyn_fxattr_list_ret <= 0 || !dyn_fxattr_has || dyn_fxattr_remove != 0) {{
        failures += 65;
    }}
    close(dyn_fd);
    int dyn_unlink_file = dyn_unlink("dyn-new.txt");
    int dyn_unlink_link = dyn_unlink("dyn.link");
    int dyn_rmdir_dir = dyn_rmdir("dyn-dir");
    printf("compat path dlsym cleanup unlink=%d unlink_link=%d rmdir=%d errno=%d\n", dyn_unlink_file, dyn_unlink_link, dyn_rmdir_dir, errno);
    if (dyn_unlink_file != 0 || dyn_unlink_link != 0 || dyn_rmdir_dir != 0) {{
        failures += 70;
    }}

    int dyn_mode_fd = open("dyn-mode.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    write(dyn_mode_fd, "dynmode", 7);
    int dyn_chmod_ret = dyn_chmod("dyn-mode.txt", 0644);
    int dyn_fchmod_ret = dyn_fchmod(dyn_mode_fd, 0600);
    int dyn_truncate_ret = dyn_truncate("dyn-mode.txt", 3);
    int dyn_ftruncate_ret = dyn_ftruncate(dyn_mode_fd, 4);
    struct stat dyn_mode_st = {{0}};
    dyn_stat("dyn-mode.txt", &dyn_mode_st);
    close(dyn_mode_fd);
    int dyn_mode_unlink = dyn_unlink("dyn-mode.txt");
    printf("compat path dlsym mode chmod=%d fchmod=%d truncate=%d ftruncate=%d size=%lld unlink=%d errno=%d\n", dyn_chmod_ret, dyn_fchmod_ret, dyn_truncate_ret, dyn_ftruncate_ret, (long long)dyn_mode_st.st_size, dyn_mode_unlink, errno);
    if (dyn_mode_fd < 0 || dyn_chmod_ret != 0 || dyn_fchmod_ret != 0 || dyn_truncate_ret != 0 || dyn_ftruncate_ret != 0 || dyn_mode_st.st_size != 4 || dyn_mode_unlink != 0) {{
        failures += 80;
    }}

    int dyn_at_fd = open("dyn-at.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    write(dyn_at_fd, "dyn-at", 6);
    int dyn_at_fchmod = dyn_fchmodat(AT_FDCWD, "dyn-at.txt", 0644, 0);
    int dyn_at_mkdirat = dyn_mkdirat(AT_FDCWD, "dyn-at-dir", 0700);
    int dyn_at_renameat = dyn_renameat(AT_FDCWD, "dyn-at.txt", AT_FDCWD, "dyn-at-new.txt");
    int dyn_at_symlink = dyn_symlink("dyn-at-new.txt", "dyn-at.link");
    char dyn_at_target[128] = {{0}};
    long dyn_at_readlinkat = (long)dyn_readlinkat(AT_FDCWD, "dyn-at.link", dyn_at_target, sizeof(dyn_at_target) - 1);
    if (dyn_at_readlinkat >= 0 && dyn_at_readlinkat < (long)sizeof(dyn_at_target)) {{
        dyn_at_target[dyn_at_readlinkat] = 0;
    }}
    int dyn_at_unlinkat = dyn_unlinkat(AT_FDCWD, "dyn-at-new.txt", 0);
    int dyn_at_unlinkat_link = dyn_unlinkat(AT_FDCWD, "dyn-at.link", 0);
    int dyn_at_rmdir = dyn_rmdir("dyn-at-dir");
    close(dyn_at_fd);
    printf("compat path dlsym at fchmodat=%d mkdirat=%d renameat=%d symlink=%d readlinkat=%ld target=%s unlinkat=%d unlink_link=%d rmdir=%d errno=%d\n", dyn_at_fchmod, dyn_at_mkdirat, dyn_at_renameat, dyn_at_symlink, dyn_at_readlinkat, dyn_at_target, dyn_at_unlinkat, dyn_at_unlinkat_link, dyn_at_rmdir, errno);
    if (dyn_at_fd < 0 || dyn_at_fchmod != 0 || dyn_at_mkdirat != 0 || dyn_at_renameat != 0 || dyn_at_symlink != 0 || dyn_at_readlinkat != 14 || !text_is(dyn_at_target, "dyn-at-new.txt") || dyn_at_unlinkat != 0 || dyn_at_unlinkat_link != 0 || dyn_at_rmdir != 0) {{
        failures += 90;
    }}

    dyn_chdir("..");
    dlclose(self);
    rmdir(base_dir);
    return failures == 0 ? 0 : 1;
}}
"#
        ),
    )
    .expect("failed to write generated arm64 path fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 path fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 path fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (binary, base_dir)
}

#[cfg(target_os = "macos")]
fn compile_arm64_env_time_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_env_time_compat.c");
    let binary = out_dir.join("arm64_env_time_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <errno.h>
#include <mach/kern_return.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

typedef char *(*getenv_fn)(const char *);
typedef int (*setenv_fn)(const char *, const char *, int);
typedef int (*unsetenv_fn)(const char *);
typedef pid_t (*getpid_fn)(void);
typedef int (*proc_pidpath_fn)(int, void *, uint32_t);
typedef int (*proc_name_fn)(int, void *, uint32_t);
typedef int (*gettimeofday_fn)(struct timeval *, void *);
typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*nanosleep_fn)(const struct timespec *, struct timespec *);
typedef uint64_t (*mach_absolute_time_fn)(void);
typedef kern_return_t (*mach_timebase_info_fn)(mach_timebase_info_t);
typedef int (*getrlimit_fn)(int, struct rlimit *);
typedef long (*sysconf_fn)(int);
typedef int (*sysctlbyname_fn)(const char *, void *, size_t *, void *, size_t);

extern int proc_pidpath(int, void *, uint32_t);
extern int proc_name(int, void *, uint32_t);

static long compatra_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    asm volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
        : "memory", "cc");
    return x0;
}

int main(void) {
    int failures = 0;

    int set_ret = setenv("COMPATRA_COMPAT_ENV", "env-ok", 1);
    char *value = getenv("COMPATRA_COMPAT_ENV");
    int unset_ret = unsetenv("COMPATRA_COMPAT_ENV");
    char *missing = getenv("COMPATRA_COMPAT_ENV");
    printf("compat env static set=%d value=%s unset=%d missing=%s errno=%d\n", set_ret, value ? value : "<null>", unset_ret, missing ? missing : "<null>", errno);
    if (set_ret != 0 || value == 0 || value[0] != 'e' || unset_ret != 0 || missing != 0) {
        failures += 10;
    }

    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();
    long syscall_pid = compatra_syscall6(0x2000014, 0, 0, 0, 0, 0, 0);
    printf("compat proc ids pid=%d ppid=%d uid=%u euid=%u gid=%u egid=%u syscall_pid=%ld\n", pid, ppid, uid, euid, gid, egid, syscall_pid);
    printf("compat proc syscall pid=%ld host_pid=%d\n", syscall_pid, pid);
    if (pid <= 0 || syscall_pid <= 0) {
        failures += 20;
    }
    char proc_path[4096] = {0};
    char proc_name_buf[1024] = {0};
    int proc_path_ret = proc_pidpath(pid, proc_path, sizeof(proc_path));
    int proc_name_ret = proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("compat proc libproc static pidpath=%d path=%s name=%d text=%s errno=%d\n", proc_path_ret, proc_path, proc_name_ret, proc_name_buf, errno);
    if (proc_path_ret <= 0 || strstr(proc_path, "arm64_env_time_compat") == 0 || proc_name_ret <= 0 || strstr(proc_name_buf, "arm64_env_time") == 0) {
        failures += 25;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    char hostname[256] = {0};
    int hostname_ret = gethostname(hostname, sizeof(hostname));
    struct utsname uts = {0};
    int uname_ret = uname(&uts);
    printf("compat system sysconf_pagesize=%ld gethostname=%d host=%s uname=%d sys=%s machine=%s\n", page_size, hostname_ret, hostname, uname_ret, uts.sysname, uts.machine);
    if (page_size <= 0 || hostname_ret != 0 || uname_ret != 0) {
        failures += 30;
    }
    char hw_machine[64] = {0};
    size_t hw_machine_len = sizeof(hw_machine);
    int hw_machine_ret = sysctlbyname("hw.machine", hw_machine, &hw_machine_len, 0, 0);
    int hw_arm64 = 0;
    size_t hw_arm64_len = sizeof(hw_arm64);
    int hw_arm64_ret = sysctlbyname("hw.optional.arm64", &hw_arm64, &hw_arm64_len, 0, 0);
    printf(
        "compat system identity uname_machine=%s hw_machine_ret=%d hw_machine=%s hw_machine_len=%lu arm64_ret=%d arm64=%d arm64_len=%lu\n",
        uts.machine,
        hw_machine_ret,
        hw_machine,
        (unsigned long)hw_machine_len,
        hw_arm64_ret,
        hw_arm64,
        (unsigned long)hw_arm64_len
    );
    if (uname_ret != 0 || strcmp(uts.machine, "arm64") != 0 || hw_machine_ret != 0 || strcmp(hw_machine, "arm64") != 0 || hw_arm64_ret != 0 || hw_arm64 != 1) {
        failures += 31;
    }

    struct timeval tv = {0};
    int gtod_ret = gettimeofday(&tv, 0);
    struct timeval syscall_tv = {0};
    uint64_t syscall_mach = 0;
    long syscall_gtod = compatra_syscall6(0x2000074, (long)&syscall_tv, 0, (long)&syscall_mach, 0, 0, 0);
    struct timespec ts = {0};
    int clock_ret = clock_gettime(CLOCK_REALTIME, &ts);
    struct timespec zero_sleep = {0, 0};
    int nanosleep_ret = nanosleep(&zero_sleep, 0);
    int usleep_ret = usleep(0);
    unsigned int sleep_ret = sleep(0);
    uint64_t mach_now = mach_absolute_time();
    mach_timebase_info_data_t timebase = {0};
    kern_return_t timebase_ret = mach_timebase_info(&timebase);
    printf("compat time gtod=%d tv=%lld.%06d syscall=%ld syscall_tv=%lld.%06d syscall_mach=%llu clock=%d ts=%lld.%09ld nanosleep=%d usleep=%d sleep=%u mach=%llu timebase=%d/%u/%u errno=%d\n",
        gtod_ret,
        (long long)tv.tv_sec,
        tv.tv_usec,
        syscall_gtod,
        (long long)syscall_tv.tv_sec,
        syscall_tv.tv_usec,
        (unsigned long long)syscall_mach,
        clock_ret,
        (long long)ts.tv_sec,
        ts.tv_nsec,
        nanosleep_ret,
        usleep_ret,
        sleep_ret,
        (unsigned long long)mach_now,
        timebase_ret,
        timebase.numer,
        timebase.denom,
        errno);
    printf("compat time imported gtod=%d clock=%d nanosleep=%d usleep=%d sleep=%u errno=%d\n", gtod_ret, clock_ret, nanosleep_ret, usleep_ret, sleep_ret, errno);
    printf("compat time syscall ret=%ld tv_sec=%lld mach=%llu\n", syscall_gtod, (long long)syscall_tv.tv_sec, (unsigned long long)syscall_mach);
    printf("compat time timebase ret=%d numer=%u denom=%u mach=%llu\n", timebase_ret, timebase.numer, timebase.denom, (unsigned long long)mach_now);
    if (gtod_ret != 0 || syscall_gtod != 0 || syscall_tv.tv_sec <= 0 || clock_ret != 0 || nanosleep_ret != 0 || usleep_ret != 0 || sleep_ret != 0 || mach_now == 0 || timebase_ret != 0 || timebase.numer == 0 || timebase.denom == 0) {
        failures += 40;
    }

    struct rlimit lim = {0};
    int rlimit_ret = getrlimit(RLIMIT_NOFILE, &lim);
    struct rlimit syscall_lim = {0};
    long syscall_rlimit = compatra_syscall6(0x20000C2, RLIMIT_NOFILE, (long)&syscall_lim, 0, 0, 0, 0);
    printf("compat rlimit static=%d cur=%llu max=%llu syscall=%ld sc_cur=%llu sc_max=%llu errno=%d\n",
        rlimit_ret,
        (unsigned long long)lim.rlim_cur,
        (unsigned long long)lim.rlim_max,
        syscall_rlimit,
        (unsigned long long)syscall_lim.rlim_cur,
        (unsigned long long)syscall_lim.rlim_max,
        errno);
    printf("compat rlimit syscall ret=%ld cur=%llu imported=%d\n", syscall_rlimit, (unsigned long long)syscall_lim.rlim_cur, rlimit_ret);
    if (rlimit_ret != 0 || syscall_rlimit != 0 || lim.rlim_cur == 0 || syscall_lim.rlim_cur == 0) {
        failures += 50;
    }

    int byname_page = 0;
    size_t byname_len = sizeof(byname_page);
    int byname_ret = sysctlbyname("hw.pagesize", &byname_page, &byname_len, 0, 0);
    int mib[2] = {CTL_HW, HW_PAGESIZE};
    int syscall_page = 0;
    size_t syscall_page_len = sizeof(syscall_page);
    long syscall_sysctl = compatra_syscall6(0x20000CA, (long)mib, 2, (long)&syscall_page, (long)&syscall_page_len, 0, 0);
    printf("compat sysctl byname=%d page=%d len=%lu syscall=%ld sc_page=%d sc_len=%lu errno=%d\n", byname_ret, byname_page, (unsigned long)byname_len, syscall_sysctl, syscall_page, (unsigned long)syscall_page_len, errno);
    printf("compat sysctl syscall ret=%ld page=%d len=%lu byname=%d\n", syscall_sysctl, syscall_page, (unsigned long)syscall_page_len, byname_ret);
    if (byname_ret != 0 || byname_page <= 0 || syscall_sysctl != 0 || syscall_page <= 0) {
        failures += 60;
    }

    void *self = dlopen(NULL, RTLD_NOW);
    getenv_fn dyn_getenv = (getenv_fn)dlsym(self, "getenv");
    setenv_fn dyn_setenv = (setenv_fn)dlsym(self, "setenv");
    unsetenv_fn dyn_unsetenv = (unsetenv_fn)dlsym(self, "unsetenv");
    getpid_fn dyn_getpid = (getpid_fn)dlsym(self, "getpid");
    proc_pidpath_fn dyn_proc_pidpath = (proc_pidpath_fn)dlsym(self, "proc_pidpath");
    proc_name_fn dyn_proc_name = (proc_name_fn)dlsym(self, "proc_name");
    gettimeofday_fn dyn_gettimeofday = (gettimeofday_fn)dlsym(self, "gettimeofday");
    clock_gettime_fn dyn_clock_gettime = (clock_gettime_fn)dlsym(self, "clock_gettime");
    nanosleep_fn dyn_nanosleep = (nanosleep_fn)dlsym(self, "nanosleep");
    mach_absolute_time_fn dyn_mach_absolute_time = (mach_absolute_time_fn)dlsym(self, "mach_absolute_time");
    mach_timebase_info_fn dyn_mach_timebase_info = (mach_timebase_info_fn)dlsym(self, "mach_timebase_info");
    getrlimit_fn dyn_getrlimit = (getrlimit_fn)dlsym(self, "getrlimit");
    sysconf_fn dyn_sysconf = (sysconf_fn)dlsym(self, "sysconf");
    sysctlbyname_fn dyn_sysctlbyname = (sysctlbyname_fn)dlsym(self, "sysctlbyname");
    printf("compat envtime dlsym ptrs env=%p pid=%p proc_pidpath=%p proc_name=%p time=%p rlimit=%p sysctl=%p\n", (void *)dyn_getenv, (void *)dyn_getpid, (void *)dyn_proc_pidpath, (void *)dyn_proc_name, (void *)dyn_gettimeofday, (void *)dyn_getrlimit, (void *)dyn_sysctlbyname);
    if (!dyn_getenv || !dyn_setenv || !dyn_unsetenv || !dyn_getpid || !dyn_proc_pidpath || !dyn_proc_name || !dyn_gettimeofday || !dyn_clock_gettime || !dyn_nanosleep || !dyn_mach_absolute_time || !dyn_mach_timebase_info || !dyn_getrlimit || !dyn_sysconf || !dyn_sysctlbyname) {
        return 70;
    }

    int dyn_set = dyn_setenv("COMPATRA_COMPAT_DYN_ENV", "dyn-ok", 1);
    char *dyn_env = dyn_getenv("COMPATRA_COMPAT_DYN_ENV");
    int dyn_unset = dyn_unsetenv("COMPATRA_COMPAT_DYN_ENV");
    char dyn_proc_path[4096] = {0};
    char dyn_proc_name_buf[1024] = {0};
    int dyn_proc_path_ret = dyn_proc_pidpath(dyn_getpid(), dyn_proc_path, sizeof(dyn_proc_path));
    int dyn_proc_name_ret = dyn_proc_name(dyn_getpid(), dyn_proc_name_buf, sizeof(dyn_proc_name_buf));
    struct timeval dyn_tv = {0};
    int dyn_gtod = dyn_gettimeofday(&dyn_tv, 0);
    struct timespec dyn_ts = {0};
    int dyn_clock = dyn_clock_gettime(CLOCK_REALTIME, &dyn_ts);
    int dyn_nano = dyn_nanosleep(&zero_sleep, 0);
    uint64_t dyn_mach = dyn_mach_absolute_time();
    mach_timebase_info_data_t dyn_timebase = {0};
    kern_return_t dyn_timebase_ret = dyn_mach_timebase_info(&dyn_timebase);
    struct rlimit dyn_lim = {0};
    int dyn_rlimit = dyn_getrlimit(RLIMIT_NOFILE, &dyn_lim);
    long dyn_page = dyn_sysconf(_SC_PAGESIZE);
    int dyn_byname_page = 0;
    size_t dyn_byname_len = sizeof(dyn_byname_page);
    int dyn_byname = dyn_sysctlbyname("hw.pagesize", &dyn_byname_page, &dyn_byname_len, 0, 0);
    printf("compat envtime dlsym env set=%d value=%s unset=%d pid=%d gtod=%d clock=%d nanosleep=%d mach=%llu timebase=%d/%u/%u rlimit=%d sysconf=%ld sysctl=%d page=%d\n",
        dyn_set,
        dyn_env ? dyn_env : "<null>",
        dyn_unset,
        dyn_getpid(),
        dyn_gtod,
        dyn_clock,
        dyn_nano,
        (unsigned long long)dyn_mach,
        dyn_timebase_ret,
        dyn_timebase.numer,
        dyn_timebase.denom,
        dyn_rlimit,
        dyn_page,
        dyn_byname,
        dyn_byname_page);
    printf("compat proc libproc dlsym pidpath=%d path=%s name=%d text=%s errno=%d\n", dyn_proc_path_ret, dyn_proc_path, dyn_proc_name_ret, dyn_proc_name_buf, errno);
    if (dyn_set != 0 || dyn_env == 0 || dyn_env[0] != 'd' || dyn_unset != 0 || dyn_getpid() <= 0 || dyn_proc_path_ret <= 0 || strstr(dyn_proc_path, "arm64_env_time_compat") == 0 || dyn_proc_name_ret <= 0 || strstr(dyn_proc_name_buf, "arm64_env_time") == 0 || dyn_gtod != 0 || dyn_clock != 0 || dyn_nano != 0 || dyn_mach == 0 || dyn_timebase_ret != 0 || dyn_timebase.numer == 0 || dyn_timebase.denom == 0 || dyn_rlimit != 0 || dyn_page <= 0 || dyn_byname != 0 || dyn_byname_page <= 0) {
        failures += 80;
    }

    dlclose(self);
    return failures == 0 ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 env/time fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-lproc")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 env/time fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 env/time fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_pthread_scheduler_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_pthread_scheduler_compat.c");
    let binary = out_dir.join("arm64_pthread_scheduler_compat");
    fs::write(
        &source,
        r#"#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t lock;
static pthread_cond_t cond;
static volatile int ready;
static volatile unsigned long spin_sink;

static void *sleeper(void *arg) {
    (void)arg;
    usleep(20);
    for (;;) {
        spin_sink++;
    }
    return 0;
}

static void *signaler(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
    return 0;
}

int main(void) {
    pthread_t slow_thread = 0;
    pthread_t signal_thread = 0;
    pthread_mutex_init(&lock, 0);
    pthread_cond_init(&cond, 0);
    pthread_create(&slow_thread, 0, sleeper, 0);
    pthread_create(&signal_thread, 0, signaler, 0);

    pthread_mutex_lock(&lock);
    while (!ready) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    printf("compat pthread scheduler ready=%d\n", ready);
    return ready == 1 ? 0 : 7;
}
"#,
    )
    .expect("failed to write generated arm64 pthread scheduler fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg("-pthread")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 pthread scheduler fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 pthread scheduler fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_dispatch_runloop_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_dispatch_runloop_compat.c");
    let binary = out_dir.join("arm64_dispatch_runloop_compat");
    fs::write(
        &source,
        r#"#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef dispatch_queue_t (*dispatch_get_main_queue_fn)(void);
typedef dispatch_queue_t (*dispatch_get_global_queue_fn)(long, unsigned long);
typedef dispatch_queue_t (*dispatch_queue_create_fn)(const char *, dispatch_queue_attr_t);
typedef void (*dispatch_async_fn)(dispatch_queue_t, dispatch_block_t);
typedef void (*dispatch_sync_fn)(dispatch_queue_t, dispatch_block_t);
typedef void (*dispatch_once_fn)(dispatch_once_t *, dispatch_block_t);
typedef void (*dispatch_async_f_fn)(dispatch_queue_t, void *, dispatch_function_t);
typedef void (*dispatch_sync_f_fn)(dispatch_queue_t, void *, dispatch_function_t);
typedef void (*dispatch_once_f_fn)(dispatch_once_t *, void *, dispatch_function_t);
typedef CFRunLoopRef (*cf_runloop_get_fn)(void);
typedef SInt32 (*cf_runloop_run_fn)(CFStringRef, CFTimeInterval, Boolean);

static volatile int once_hits;
static volatile int sync_hits;
static volatile int async_hits;

static void bump_context(void *ctx) {
    int *value = (int *)ctx;
    *value += 5;
}

static dispatch_queue_t static_get_main_queue(void) {
    return dispatch_get_main_queue();
}

static dispatch_queue_t static_get_global_queue(long identifier, unsigned long flags) {
    return dispatch_get_global_queue(identifier, flags);
}

static dispatch_queue_t static_queue_create(const char *label, dispatch_queue_attr_t attr) {
    return dispatch_queue_create(label, attr);
}

static void static_dispatch_async(dispatch_queue_t queue, dispatch_block_t block) {
    dispatch_async(queue, block);
}

static void static_dispatch_sync(dispatch_queue_t queue, dispatch_block_t block) {
    dispatch_sync(queue, block);
}

static void static_dispatch_once(dispatch_once_t *token, dispatch_block_t block) {
    dispatch_once(token, block);
}

static void static_dispatch_async_f(dispatch_queue_t queue, void *context, dispatch_function_t work) {
    dispatch_async_f(queue, context, work);
}

static void static_dispatch_sync_f(dispatch_queue_t queue, void *context, dispatch_function_t work) {
    dispatch_sync_f(queue, context, work);
}

static void static_dispatch_once_f(dispatch_once_t *token, void *context, dispatch_function_t work) {
    dispatch_once_f(token, context, work);
}

static int probe_dispatch(
    const char *label,
    dispatch_get_main_queue_fn get_main_queue,
    dispatch_get_global_queue_fn get_global_queue,
    dispatch_queue_create_fn queue_create,
    dispatch_async_fn async_call,
    dispatch_sync_fn sync_call,
    dispatch_once_fn once_call,
    dispatch_async_f_fn async_f_call,
    dispatch_sync_f_fn sync_f_call,
    dispatch_once_f_fn once_f_call,
    cf_runloop_get_fn runloop_get,
    cf_runloop_run_fn runloop_run
) {
    int once_before = once_hits;
    int sync_before = sync_hits;
    int async_before = async_hits;
    int context = 0;
    dispatch_once_t once_token = 0;
    dispatch_once_t once_f_token = 0;

    dispatch_queue_t main_queue = get_main_queue ? get_main_queue() : 0;
    dispatch_queue_t global_queue = get_global_queue ? get_global_queue(0, 0) : main_queue;
    dispatch_queue_t queue = queue_create ? queue_create("compatra.dispatch.fixture", 0) : global_queue;
    dispatch_queue_t target_queue = queue ? queue : (global_queue ? global_queue : main_queue);

    if (once_call) {
        once_call(&once_token, ^{
            once_hits += 1;
        });
        once_call(&once_token, ^{
            once_hits += 100;
        });
    }
    if (sync_call) {
        sync_call(target_queue, ^{
            sync_hits += 2;
        });
    }
    if (async_call) {
        async_call(target_queue, ^{
            async_hits += 3;
        });
    }
    if (once_f_call) {
        once_f_call(&once_f_token, &context, bump_context);
        once_f_call(&once_f_token, &context, bump_context);
    }
    if (sync_f_call) {
        sync_f_call(target_queue, &context, bump_context);
    }
    if (async_f_call) {
        async_f_call(target_queue, &context, bump_context);
    }

    CFRunLoopRef runloop = runloop_get ? runloop_get() : 0;
    SInt32 run_result = runloop_run ? runloop_run(kCFRunLoopDefaultMode, 0.0, true) : -1;

    int once_delta = once_hits - once_before;
    int sync_delta = sync_hits - sync_before;
    int async_delta = async_hits - async_before;
    int pass = target_queue && once_delta == 1 && sync_delta == 2 && async_delta == 3 && context == 15 && runloop && run_result == 3;
    printf(
        "compat dispatch %s main=%p global=%p queue=%p once=%d sync=%d async=%d context=%d runloop=%p run=%d pass=%d\n",
        label,
        main_queue,
        global_queue,
        queue,
        once_delta,
        sync_delta,
        async_delta,
        context,
        runloop,
        run_result,
        pass
    );
    return pass ? 0 : 1;
}

int main(void) {
    int failures = 0;
    failures += probe_dispatch(
        "static",
        static_get_main_queue,
        static_get_global_queue,
        static_queue_create,
        static_dispatch_async,
        static_dispatch_sync,
        static_dispatch_once,
        static_dispatch_async_f,
        static_dispatch_sync_f,
        static_dispatch_once_f,
        CFRunLoopGetCurrent,
        CFRunLoopRunInMode
    );

    void *dispatch = dlopen("/usr/lib/system/libdispatch.dylib", RTLD_NOW);
    void *core_foundation = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    dispatch_get_main_queue_fn dyn_get_main_queue = (dispatch_get_main_queue_fn)dlsym(dispatch, "dispatch_get_main_queue");
    dispatch_get_global_queue_fn dyn_get_global_queue = (dispatch_get_global_queue_fn)dlsym(dispatch, "dispatch_get_global_queue");
    dispatch_queue_create_fn dyn_queue_create = (dispatch_queue_create_fn)dlsym(dispatch, "dispatch_queue_create");
    dispatch_async_fn dyn_async = (dispatch_async_fn)dlsym(dispatch, "dispatch_async");
    dispatch_sync_fn dyn_sync = (dispatch_sync_fn)dlsym(dispatch, "dispatch_sync");
    dispatch_once_fn dyn_once = (dispatch_once_fn)dlsym(dispatch, "dispatch_once");
    dispatch_async_f_fn dyn_async_f = (dispatch_async_f_fn)dlsym(dispatch, "dispatch_async_f");
    dispatch_sync_f_fn dyn_sync_f = (dispatch_sync_f_fn)dlsym(dispatch, "dispatch_sync_f");
    dispatch_once_f_fn dyn_once_f = (dispatch_once_f_fn)dlsym(dispatch, "dispatch_once_f");
    cf_runloop_get_fn dyn_runloop_get = (cf_runloop_get_fn)dlsym(core_foundation, "CFRunLoopGetCurrent");
    cf_runloop_run_fn dyn_runloop_run = (cf_runloop_run_fn)dlsym(core_foundation, "CFRunLoopRunInMode");

    printf(
        "compat dispatch dlsym ptrs main=%p global=%p create=%p async=%p sync=%p once=%p async_f=%p sync_f=%p once_f=%p runloop=%p run=%p\n",
        dyn_get_main_queue,
        dyn_get_global_queue,
        dyn_queue_create,
        dyn_async,
        dyn_sync,
        dyn_once,
        dyn_async_f,
        dyn_sync_f,
        dyn_once_f,
        dyn_runloop_get,
        dyn_runloop_run
    );
    if (!dyn_get_global_queue || !dyn_queue_create || !dyn_async || !dyn_sync || !dyn_once || !dyn_async_f || !dyn_sync_f || !dyn_once_f || !dyn_runloop_get || !dyn_runloop_run) {
        return 20;
    }
    failures += probe_dispatch(
        "dlsym",
        dyn_get_main_queue,
        dyn_get_global_queue,
        dyn_queue_create,
        dyn_async,
        dyn_sync,
        dyn_once,
        dyn_async_f,
        dyn_sync_f,
        dyn_once_f,
        dyn_runloop_get,
        dyn_runloop_run
    );
    return failures == 0 ? 0 : 30 + failures;
}
"#,
    )
    .expect("failed to write generated arm64 dispatch/runloop fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fblocks")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-framework")
        .arg("CoreFoundation")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 dispatch/runloop fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 dispatch/runloop fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_directory_entropy_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_directory_entropy_compat.c");
    let binary = out_dir.join("arm64_directory_entropy_compat");
    let base_dir = out_dir.join("dir-host-root");
    fs::write(
        &source,
        format!(
            r#"#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

typedef DIR *(*opendir_fn)(const char *);
typedef DIR *(*fdopendir_fn)(int);
typedef struct dirent *(*readdir_fn)(DIR *);
typedef int (*readdir_r_fn)(DIR *, struct dirent *, struct dirent **);
typedef int (*closedir_fn)(DIR *);
typedef int (*dirfd_fn)(DIR *);
typedef void (*rewinddir_fn)(DIR *);
typedef long (*telldir_fn)(DIR *);
typedef void (*seekdir_fn)(DIR *, long);
typedef int (*scandir_fn)(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **));
typedef int (*alphasort_fn)(const struct dirent **, const struct dirent **);
typedef int (*glob_fn)(const char *, int, int (*)(const char *, int), glob_t *);
typedef void (*globfree_fn)(glob_t *);
typedef int (*getattrlist_fn)(const char *, void *, void *, size_t, unsigned int);
typedef int (*getentropy_fn)(void *, size_t);

extern int getentropy(void *, size_t);

static long compatra_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x16 __asm__("x16") = num;
    asm volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
        : "memory", "cc");
    return x0;
}}

static int streq(const char *a, const char *b) {{
    while (*a && *b && *a == *b) {{
        a++;
        b++;
    }}
    return *a == 0 && *b == 0;
}}

static int any_nonzero(const unsigned char *buf, unsigned long len) {{
    for (unsigned long i = 0; i < len; i++) {{
        if (buf[i] != 0) {{
            return 1;
        }}
    }}
    return 0;
}}

static void fixture_dir_from_argv0(const char *argv0, char *out, size_t out_len) {{
    if (out_len == 0) {{
        return;
    }}
    (void)argv0;
    snprintf(out, out_len, ".");
}}

static void join_path(const char *base, const char *name, char *out, size_t out_len) {{
    if (strcmp(base, "/") == 0) {{
        snprintf(out, out_len, "/%s", name);
    }} else {{
        snprintf(out, out_len, "%s/%s", base, name);
    }}
}}

static void fixture_dir_from_optional_arg(int argc, char **argv, const char *argv0, char *out, size_t out_len) {{
    if (argc > 1 && argv && argv[1] && argv[1][0]) {{
        snprintf(out, out_len, "%s", argv[1]);
    }} else {{
        fixture_dir_from_argv0(argv0, out, out_len);
    }}
}}

static void write_file(const char *path, const char *text) {{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd >= 0) {{
        const char *p = text;
        unsigned long len = 0;
        while (p[len] != 0) {{
            len++;
        }}
        write(fd, text, len);
        close(fd);
    }}
}}

static int scan_with_readdir(const char *label, DIR *dir, readdir_fn read_dir, rewinddir_fn rewind_dir, telldir_fn tell_dir, seekdir_fn seek_dir) {{
    int alpha = 0;
    int beta = 0;
    int entries = 0;
    long start = tell_dir ? tell_dir(dir) : 0;
    struct dirent *first = read_dir(dir);
    const char *first_name = first ? first->d_name : "<null>";
    if (seek_dir) {{
        seek_dir(dir, start);
    }}
    struct dirent *again = read_dir(dir);
    const char *again_name = again ? again->d_name : "<null>";
    if (rewind_dir) {{
        rewind_dir(dir);
    }}
    struct dirent *entry = 0;
    while ((entry = read_dir(dir)) != 0) {{
        entries++;
        if (streq(entry->d_name, "alpha.txt")) {{
            alpha = 1;
        }}
        if (streq(entry->d_name, "beta.txt")) {{
            beta = 1;
        }}
    }}
    printf("compat dir %s seen alpha=%d beta=%d entries=%d first=%s again=%s errno=%d\n", label, alpha, beta, entries, first_name, again_name, errno);
    return alpha && beta ? 0 : 1;
}}

static int scan_with_readdir_r(const char *label, DIR *dir, readdir_r_fn read_dir_r) {{
    int alpha = 0;
    int beta = 0;
    int entries = 0;
    int last_ret = 0;
    for (;;) {{
        struct dirent storage;
        struct dirent *result = 0;
        last_ret = read_dir_r(dir, &storage, &result);
        if (last_ret != 0 || result == 0) {{
            break;
        }}
        entries++;
        if (streq(storage.d_name, "alpha.txt")) {{
            alpha = 1;
        }}
        if (streq(storage.d_name, "beta.txt")) {{
            beta = 1;
        }}
    }}
    printf("compat dir %s readdir_r ret=%d alpha=%d beta=%d entries=%d errno=%d\n", label, last_ret, alpha, beta, entries, errno);
    return last_ret == 0 && alpha && beta ? 0 : 1;
}}

static int scan_with_scandir(const char *label, const char *base_dir, scandir_fn scan_dir, alphasort_fn alpha_sort) {{
    struct dirent **names = 0;
    errno = 0;
    int count = scan_dir(base_dir, &names, 0, alpha_sort);
    int alpha = 0;
    int beta = 0;
    char first[256] = {{0}};
    char last[256] = {{0}};
    snprintf(first, sizeof(first), "%s", count > 0 && names && names[0] ? names[0]->d_name : "<none>");
    snprintf(last, sizeof(last), "%s", count > 0 && names && names[count - 1] ? names[count - 1]->d_name : "<none>");
    for (int i = 0; names && i < count; i++) {{
        if (names[i]) {{
            if (streq(names[i]->d_name, "alpha.txt")) {{
                alpha = 1;
            }}
            if (streq(names[i]->d_name, "beta.txt")) {{
                beta = 1;
            }}
            free(names[i]);
        }}
    }}
    free(names);
    printf("compat dir %s scandir count=%d alpha=%d beta=%d first=%s last=%s errno=%d\n", label, count, alpha, beta, first, last, errno);
    return count >= 2 && alpha && beta ? 0 : 1;
}}

static int scan_with_glob(const char *label, const char *pattern, glob_fn glob_call, globfree_fn glob_free) {{
    glob_t globbuf;
    memset(&globbuf, 0, sizeof(globbuf));
    errno = 0;
    int ret = glob_call(pattern, 0, 0, &globbuf);
    int alpha = 0;
    int beta = 0;
    const char *first = globbuf.gl_pathc > 0 && globbuf.gl_pathv ? globbuf.gl_pathv[0] : "<none>";
    size_t count = globbuf.gl_pathc;
    for (size_t i = 0; ret == 0 && globbuf.gl_pathv && i < globbuf.gl_pathc; i++) {{
        const char *path = globbuf.gl_pathv[i];
        if (path && strstr(path, "alpha.txt")) {{
            alpha = 1;
        }}
        if (path && strstr(path, "beta.txt")) {{
            beta = 1;
        }}
    }}
    printf("compat dir %s glob ret=%d count=%zu alpha=%d beta=%d first=%s errno=%d\n", label, ret, globbuf.gl_pathc, alpha, beta, first, errno);
    glob_free(&globbuf);
    return ret == 0 && count >= 2 && alpha && beta ? 0 : 1;
}}

static int probe_getattrlist(const char *label, const char *path, getattrlist_fn get_attrs) {{
    struct attrlist attrs;
    unsigned char buffer[512];
    memset(&attrs, 0, sizeof(attrs));
    memset(buffer, 0, sizeof(buffer));
    attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrs.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FILEID;
    attrs.fileattr = ATTR_FILE_TOTALSIZE | ATTR_FILE_DATALENGTH;
    errno = 0;
    int ret = get_attrs(path, &attrs, buffer, sizeof(buffer), 0);
    uint32_t len = 0;
    if (ret == 0) {{
        memcpy(&len, buffer, sizeof(len));
    }}
    printf("compat dir %s getattrlist ret=%d len=%u errno=%d\n", label, ret, len, errno);
    return ret == 0 && len > 4 ? 0 : 1;
}}

int main(int argc, char **argv) {{
    int failures = 0;
    const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : ".";
    char fixture_dir[4096] = {{0}};
    char base_dir[4096] = {{0}};
    char alpha_file[4096] = {{0}};
    char beta_file[4096] = {{0}};
    char glob_pattern[4096] = {{0}};
    fixture_dir_from_optional_arg(argc, argv, argv0, fixture_dir, sizeof(fixture_dir));
    join_path(fixture_dir, "dir-host-root", base_dir, sizeof(base_dir));
    join_path(base_dir, "alpha.txt", alpha_file, sizeof(alpha_file));
    join_path(base_dir, "beta.txt", beta_file, sizeof(beta_file));
    snprintf(glob_pattern, sizeof(glob_pattern), "%s/*.txt", base_dir);
    printf(
        "compat dir paths argc=%d argv1=%s fixture_dir=%s base=%s alpha=%s beta=%s\n",
        argc,
        (argc > 1 && argv && argv[1]) ? argv[1] : "<none>",
        fixture_dir,
        base_dir,
        alpha_file,
        beta_file
    );
    mkdir(base_dir, 0700);
    write_file(alpha_file, "a");
    write_file(beta_file, "b");

    DIR *dir = opendir(base_dir);
    int static_fd = dir ? dirfd(dir) : -1;
    printf("compat dir static opendir=%p dirfd=%d errno=%d\n", dir, static_fd, errno);
    if (!dir || static_fd < 0) {{
        return 10;
    }}
    failures += scan_with_readdir("static", dir, readdir, rewinddir, telldir, seekdir);
    closedir(dir);

    int fd = open(base_dir, O_RDONLY);
    DIR *fd_dir = fdopendir(fd);
    printf("compat dir fdopendir fd=%d dir=%p errno=%d\n", fd, fd_dir, errno);
    if (!fd_dir) {{
        failures += 20;
        if (fd >= 0) {{
            close(fd);
        }}
    }} else {{
        failures += scan_with_readdir("fdopendir", fd_dir, readdir, rewinddir, telldir, seekdir);
        closedir(fd_dir);
    }}

    DIR *rr_dir = opendir(base_dir);
    failures += rr_dir ? scan_with_readdir_r("static", rr_dir, readdir_r) : 30;
    if (rr_dir) {{
        closedir(rr_dir);
    }}

    failures += scan_with_scandir("static", base_dir, scandir, alphasort);
    failures += scan_with_glob("static", glob_pattern, glob, globfree);
    failures += probe_getattrlist("static", alpha_file, getattrlist);

    unsigned char entropy[16] = {{0}};
    int entropy_ret = getentropy(entropy, sizeof(entropy));
    unsigned char syscall_entropy[16] = {{0}};
    long syscall_entropy_ret = compatra_syscall6(0x20001F4, (long)syscall_entropy, sizeof(syscall_entropy), 0, 0, 0, 0);
    printf("compat entropy static ret=%d nonzero=%d syscall=%ld sc_nonzero=%d errno=%d\n", entropy_ret, any_nonzero(entropy, sizeof(entropy)), syscall_entropy_ret, any_nonzero(syscall_entropy, sizeof(syscall_entropy)), errno);
    if (entropy_ret != 0 || !any_nonzero(entropy, sizeof(entropy)) || syscall_entropy_ret != 0 || !any_nonzero(syscall_entropy, sizeof(syscall_entropy))) {{
        failures += 40;
    }}

    void *self = dlopen(NULL, RTLD_NOW);
    opendir_fn dyn_opendir = (opendir_fn)dlsym(self, "opendir");
    fdopendir_fn dyn_fdopendir = (fdopendir_fn)dlsym(self, "fdopendir");
    readdir_fn dyn_readdir = (readdir_fn)dlsym(self, "readdir");
    readdir_r_fn dyn_readdir_r = (readdir_r_fn)dlsym(self, "readdir_r");
    closedir_fn dyn_closedir = (closedir_fn)dlsym(self, "closedir");
    dirfd_fn dyn_dirfd = (dirfd_fn)dlsym(self, "dirfd");
    rewinddir_fn dyn_rewinddir = (rewinddir_fn)dlsym(self, "rewinddir");
    telldir_fn dyn_telldir = (telldir_fn)dlsym(self, "telldir");
    seekdir_fn dyn_seekdir = (seekdir_fn)dlsym(self, "seekdir");
    scandir_fn dyn_scandir = (scandir_fn)dlsym(self, "scandir");
    alphasort_fn dyn_alphasort = (alphasort_fn)dlsym(self, "alphasort");
    glob_fn dyn_glob = (glob_fn)dlsym(self, "glob");
    globfree_fn dyn_globfree = (globfree_fn)dlsym(self, "globfree");
    getattrlist_fn dyn_getattrlist = (getattrlist_fn)dlsym(self, "getattrlist");
    getentropy_fn dyn_getentropy = (getentropy_fn)dlsym(self, "getentropy");
    printf("compat dir dlsym ptrs opendir=%p readdir=%p closedir=%p dirfd=%p scandir=%p glob=%p getattrlist=%p entropy=%p\n", (void *)dyn_opendir, (void *)dyn_readdir, (void *)dyn_closedir, (void *)dyn_dirfd, (void *)dyn_scandir, (void *)dyn_glob, (void *)dyn_getattrlist, (void *)dyn_getentropy);
    if (!dyn_opendir || !dyn_fdopendir || !dyn_readdir || !dyn_readdir_r || !dyn_closedir || !dyn_dirfd || !dyn_rewinddir || !dyn_telldir || !dyn_seekdir || !dyn_scandir || !dyn_alphasort || !dyn_glob || !dyn_globfree || !dyn_getattrlist || !dyn_getentropy) {{
        return 50;
    }}

    DIR *dyn_dir = dyn_opendir(base_dir);
    int dyn_fd = dyn_dir ? dyn_dirfd(dyn_dir) : -1;
    printf("compat dir dlsym opendir=%p dirfd=%d errno=%d\n", dyn_dir, dyn_fd, errno);
    failures += dyn_dir ? scan_with_readdir("dlsym", dyn_dir, dyn_readdir, dyn_rewinddir, dyn_telldir, dyn_seekdir) : 60;
    if (dyn_dir) {{
        dyn_closedir(dyn_dir);
    }}

    int dyn_raw_fd = open(base_dir, O_RDONLY);
    DIR *dyn_fd_dir = dyn_fdopendir(dyn_raw_fd);
    failures += dyn_fd_dir ? scan_with_readdir_r("dlsym", dyn_fd_dir, dyn_readdir_r) : 70;
    if (dyn_fd_dir) {{
        dyn_closedir(dyn_fd_dir);
    }} else if (dyn_raw_fd >= 0) {{
        close(dyn_raw_fd);
    }}

    failures += scan_with_scandir("dlsym", base_dir, dyn_scandir, dyn_alphasort);
    failures += scan_with_glob("dlsym", glob_pattern, dyn_glob, dyn_globfree);
    failures += probe_getattrlist("dlsym", beta_file, dyn_getattrlist);

    unsigned char dyn_entropy[16] = {{0}};
    int dyn_entropy_ret = dyn_getentropy(dyn_entropy, sizeof(dyn_entropy));
    printf("compat entropy dlsym ret=%d nonzero=%d errno=%d\n", dyn_entropy_ret, any_nonzero(dyn_entropy, sizeof(dyn_entropy)), errno);
    if (dyn_entropy_ret != 0 || !any_nonzero(dyn_entropy, sizeof(dyn_entropy))) {{
        failures += 80;
    }}

    dlclose(self);
    unlink(alpha_file);
    unlink(beta_file);
    rmdir(base_dir);
    return failures == 0 ? 0 : 1;
}}
"#
        ),
    )
    .expect("failed to write generated arm64 directory/entropy fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 directory/entropy fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 directory/entropy fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (binary, base_dir)
}

#[cfg(target_os = "macos")]
fn compile_arm64_apple_framework_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_apple_framework_compat.c");
    let binary = out_dir.join("arm64_apple_framework_compat");
    fs::write(
        &source,
        r#"#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef CFStringRef (*cf_create_cstr_fn)(CFAllocatorRef, const char *, CFStringEncoding);
typedef Boolean (*cf_get_cstr_fn)(CFStringRef, char *, CFIndex, CFStringEncoding);
typedef CFIndex (*cf_get_len_fn)(CFStringRef);
typedef CFDataRef (*cf_data_create_fn)(CFAllocatorRef, const UInt8 *, CFIndex);
typedef CFIndex (*cf_data_get_len_fn)(CFDataRef);
typedef const UInt8 *(*cf_data_get_bytes_fn)(CFDataRef);
typedef CFTypeID (*cf_get_type_id_fn)(CFTypeRef);
typedef CFTypeID (*cf_type_id_fn)(void);
typedef CFURLRef (*cf_url_create_string_fn)(CFAllocatorRef, CFStringRef, CFURLRef);
typedef CFStringRef (*cf_url_get_string_fn)(CFURLRef);
typedef CFMutableArrayRef (*cf_array_create_mutable_fn)(CFAllocatorRef, CFIndex, const CFArrayCallBacks *);
typedef void (*cf_array_mutate_fn)(CFMutableArrayRef, const void *);
typedef void (*cf_array_index_mutate_fn)(CFMutableArrayRef, CFIndex, const void *);
typedef void (*cf_array_remove_fn)(CFMutableArrayRef, CFIndex);
typedef void (*cf_array_remove_all_fn)(CFMutableArrayRef);
typedef Boolean (*cf_array_contains_fn)(CFArrayRef, CFRange, const void *);
typedef CFIndex (*cf_array_get_count_fn)(CFArrayRef);
typedef const void *(*cf_array_get_value_fn)(CFArrayRef, CFIndex);
typedef CFSetRef (*cf_set_create_fn)(CFAllocatorRef, const void **, CFIndex, const CFSetCallBacks *);
typedef CFMutableSetRef (*cf_set_create_mutable_fn)(CFAllocatorRef, CFIndex, const CFSetCallBacks *);
typedef void (*cf_set_mutate_fn)(CFMutableSetRef, const void *);
typedef void (*cf_set_remove_all_fn)(CFMutableSetRef);
typedef Boolean (*cf_set_contains_fn)(CFSetRef, const void *);
typedef CFIndex (*cf_set_get_count_fn)(CFSetRef);
typedef const void *(*cf_set_get_value_fn)(CFSetRef, const void *);
typedef Boolean (*cf_set_get_value_if_present_fn)(CFSetRef, const void *, const void **);
typedef CFMutableDictionaryRef (*cf_dictionary_create_mutable_fn)(CFAllocatorRef, CFIndex, const CFDictionaryKeyCallBacks *, const CFDictionaryValueCallBacks *);
typedef void (*cf_dictionary_mutate_fn)(CFMutableDictionaryRef, const void *, const void *);
typedef void (*cf_dictionary_remove_fn)(CFMutableDictionaryRef, const void *);
typedef void (*cf_dictionary_remove_all_fn)(CFMutableDictionaryRef);
typedef const void *(*cf_dictionary_get_value_fn)(CFDictionaryRef, const void *);
typedef CFIndex (*cf_dictionary_get_count_fn)(CFDictionaryRef);
typedef int (*sec_random_fn)(void *, size_t, uint8_t *);
typedef CFStringRef (*sec_error_fn)(OSStatus, void *);
typedef OSStatus (*sec_item_copy_matching_fn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*sec_item_add_fn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*sec_item_delete_fn)(CFDictionaryRef);
typedef OSStatus (*sec_keychain_copy_default_fn)(SecKeychainRef *);
typedef OSStatus (*sec_keychain_open_fn)(const char *, SecKeychainRef *);
typedef OSStatus (*sec_keychain_get_path_fn)(SecKeychainRef, UInt32 *, char *);
typedef OSStatus (*sec_keychain_find_generic_password_fn)(CFTypeRef, UInt32, const char *, UInt32, const char *, UInt32 *, void **, SecKeychainItemRef *);
typedef OSStatus (*sec_keychain_search_create_fn)(CFTypeRef, SecItemClass, const SecKeychainAttributeList *, SecKeychainSearchRef *);
typedef OSStatus (*sec_keychain_search_next_fn)(SecKeychainSearchRef, SecKeychainItemRef *);
typedef OSStatus (*sec_keychain_item_copy_content_fn)(SecKeychainItemRef, SecItemClass *, SecKeychainAttributeList *, UInt32 *, void **);
typedef OSStatus (*sec_keychain_item_free_content_fn)(SecKeychainAttributeList *, void *);
typedef CFMutableDictionaryRef (*io_service_matching_fn)(const char *);
typedef io_service_t (*io_service_get_matching_service_fn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*io_registry_entry_get_name_fn)(io_registry_entry_t, io_name_t);
typedef kern_return_t (*io_registry_entry_get_path_fn)(io_registry_entry_t, const io_name_t, io_string_t);
typedef kern_return_t (*io_registry_entry_get_registry_entry_id_fn)(io_registry_entry_t, uint64_t *);
typedef CFTypeRef (*io_registry_entry_create_cf_property_fn)(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);
typedef kern_return_t (*io_object_release_fn)(io_object_t);

static int any_nonzero(const unsigned char *buf, unsigned long len) {
    for (unsigned long i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 1;
        }
    }
    return 0;
}

static CFStringRef compat_cfstr(const char *text) {
    return CFStringCreateWithCString(0, text, kCFStringEncodingUTF8);
}

static int exercise_cfurl(
    const char *label,
    cf_create_cstr_fn create_str,
    cf_get_cstr_fn get_str,
    cf_url_create_string_fn create_url,
    cf_url_get_string_fn get_url_string
) {
    if (!create_str || !get_str || !create_url || !get_url_string) {
        return 0;
    }

    const char *url_text = "https://example.com/compatra?mode=compat";
    CFStringRef url_input = create_str(0, url_text, kCFStringEncodingUTF8);
    CFURLRef url = url_input ? create_url(0, url_input, 0) : 0;
    CFStringRef roundtrip = url ? get_url_string(url) : 0;
    char out[128] = {0};
    int text_ok = roundtrip ? get_str(roundtrip, out, sizeof(out), kCFStringEncodingUTF8) : 0;
    int ok = url && text_ok && strcmp(out, url_text) == 0;
    printf(
        "compat cfurl %s url=%p text_ok=%d text=%s pass=%d\n",
        label,
        (void *)url,
        text_ok,
        out,
        ok
    );
    return ok ? 1 : 0;
}

static CFDictionaryRef make_secitem_query(const char *service, const char *account, int include_value) {
    CFStringRef key_class = kSecClass;
    CFStringRef key_service = kSecAttrService;
    CFStringRef key_account = kSecAttrAccount;
    CFStringRef key_value_data = include_value ? kSecValueData : 0;
    CFStringRef value_class = kSecClassGenericPassword;
    CFStringRef value_service = compat_cfstr(service);
    CFStringRef value_account = compat_cfstr(account);
    CFDataRef value_data = include_value ? CFDataCreate(0, (const UInt8 *)"compatra-secitem-bridge", 23) : 0;
    const void *keys[4] = {key_class, key_service, key_account, key_value_data};
    const void *values[4] = {value_class, value_service, value_account, value_data};
    CFIndex count = include_value ? 4 : 3;
    if (!key_class || !key_service || !key_account || !value_class || !value_service || !value_account || (include_value && (!key_value_data || !value_data))) {
        return 0;
    }
    return CFDictionaryCreate(0, keys, values, count, 0, 0);
}

static CFMutableDictionaryRef make_secitem_mutable_query_with(
    const char *service,
    const char *account,
    int include_value,
    cf_dictionary_create_mutable_fn create_impl,
    cf_dictionary_mutate_fn set_impl,
    cf_dictionary_mutate_fn add_impl,
    cf_dictionary_mutate_fn replace_impl,
    cf_dictionary_remove_fn remove_impl,
    cf_dictionary_remove_all_fn remove_all_impl,
    cf_dictionary_get_value_fn get_impl,
    cf_dictionary_get_count_fn count_impl,
    int *ops_ok
) {
    if (ops_ok) {
        *ops_ok = 0;
    }
    if (!create_impl || !set_impl || !add_impl || !replace_impl || !remove_impl || !remove_all_impl || !get_impl || !count_impl) {
        return 0;
    }
    if (!kSecClass || !kSecAttrService || !kSecAttrAccount || !kSecClassGenericPassword || (include_value && !kSecValueData)) {
        return 0;
    }

    CFMutableDictionaryRef query = create_impl(0, 0, 0, 0);
    if (!query) {
        return 0;
    }

    CFStringRef value_service = compat_cfstr(service);
    CFStringRef value_account = compat_cfstr(account);
    CFStringRef value_account_replacement = compat_cfstr(account);
    const char value_payload[] = "compatra-secitem-mutable";
    CFDataRef value_data = include_value ? CFDataCreate(0, (const UInt8 *)value_payload, (CFIndex)strlen(value_payload)) : 0;
    if (!value_service || !value_account || !value_account_replacement || (include_value && !value_data)) {
        return 0;
    }

    set_impl(query, kSecClass, kSecClassGenericPassword);
    set_impl(query, kSecAttrService, value_service);
    set_impl(query, kSecAttrAccount, value_account);
    replace_impl(query, kSecAttrAccount, value_account_replacement);
    if (include_value) {
        set_impl(query, kSecValueData, value_data);
    }

    CFStringRef temp_key = compat_cfstr("compatra-temp-key");
    CFStringRef temp_value = compat_cfstr("compatra-temp-value");
    add_impl(query, temp_key, temp_value);
    const void *temp_found = get_impl(query, temp_key);
    remove_impl(query, temp_key);
    const void *temp_removed = get_impl(query, temp_key);

    CFMutableDictionaryRef scratch = create_impl(0, 0, 0, 0);
    if (scratch) {
        set_impl(scratch, temp_key, temp_value);
        remove_all_impl(scratch);
    }
    int local_ops_ok = temp_found && !temp_removed && scratch && count_impl(scratch) == 0;
    if (ops_ok) {
        *ops_ok = local_ops_ok;
    }
    return local_ops_ok ? query : 0;
}

static CFMutableDictionaryRef make_secitem_mutable_query(const char *service, const char *account, int include_value, int *ops_ok) {
    return make_secitem_mutable_query_with(
        service,
        account,
        include_value,
        CFDictionaryCreateMutable,
        CFDictionarySetValue,
        CFDictionaryAddValue,
        CFDictionaryReplaceValue,
        CFDictionaryRemoveValue,
        CFDictionaryRemoveAllValues,
        CFDictionaryGetValue,
        CFDictionaryGetCount,
        ops_ok
    );
}

static int exercise_cfarray(
    const char *label,
    cf_create_cstr_fn create_str,
    cf_array_create_mutable_fn create_array,
    cf_array_mutate_fn append_impl,
    cf_array_index_mutate_fn insert_impl,
    cf_array_index_mutate_fn set_impl,
    cf_array_remove_fn remove_impl,
    cf_array_remove_all_fn remove_all_impl,
    cf_array_contains_fn contains_impl,
    cf_array_get_count_fn count_impl,
    cf_array_get_value_fn get_impl
) {
    if (!create_str || !create_array || !append_impl || !insert_impl || !set_impl || !remove_impl || !remove_all_impl || !contains_impl || !count_impl || !get_impl) {
        return 0;
    }

    CFMutableArrayRef array = create_array(0, 0, 0);
    CFStringRef alpha = create_str(0, "alpha", kCFStringEncodingUTF8);
    CFStringRef beta = create_str(0, "beta", kCFStringEncodingUTF8);
    CFStringRef gamma = create_str(0, "gamma", kCFStringEncodingUTF8);
    CFStringRef delta = create_str(0, "delta", kCFStringEncodingUTF8);
    if (!array || !alpha || !beta || !gamma || !delta) {
        printf("compat cfarray %s array=%p setup=0 pass=0\n", label, (void *)array);
        return 0;
    }

    append_impl(array, alpha);
    append_impl(array, beta);
    insert_impl(array, 1, gamma);
    set_impl(array, 2, delta);

    CFIndex count_before = count_impl(array);
    CFRange full = CFRangeMake(0, count_before);
    int contains_gamma = contains_impl(array, full, gamma);
    const void *first_before = get_impl(array, 0);
    const void *second_before = get_impl(array, 1);
    const void *third_before = get_impl(array, 2);

    remove_impl(array, 0);
    CFIndex count_after_remove = count_impl(array);
    const void *first_after_remove = get_impl(array, 0);
    remove_all_impl(array);
    CFIndex count_after_clear = count_impl(array);

    int ok = count_before == 3
        && contains_gamma
        && first_before == alpha
        && second_before == gamma
        && third_before == delta
        && count_after_remove == 2
        && first_after_remove == gamma
        && count_after_clear == 0;
    printf(
        "compat cfarray %s array=%p count=%ld contains_gamma=%d first_ok=%d second_ok=%d third_ok=%d after_remove=%ld after_first_ok=%d empty=%ld pass=%d\n",
        label,
        (void *)array,
        (long)count_before,
        contains_gamma,
        first_before == alpha,
        second_before == gamma,
        third_before == delta,
        (long)count_after_remove,
        first_after_remove == gamma,
        (long)count_after_clear,
        ok
    );
    return ok ? 1 : 0;
}

static int exercise_cfset(
    const char *label,
    cf_create_cstr_fn create_str,
    cf_set_create_fn create_set,
    cf_set_create_mutable_fn create_mutable_set,
    cf_set_mutate_fn add_impl,
    cf_set_mutate_fn set_impl,
    cf_set_mutate_fn replace_impl,
    cf_set_mutate_fn remove_impl,
    cf_set_remove_all_fn remove_all_impl,
    cf_set_contains_fn contains_impl,
    cf_set_get_count_fn count_impl,
    cf_set_get_value_fn get_impl,
    cf_set_get_value_if_present_fn get_if_present_impl
) {
    if (!create_str || !create_set || !create_mutable_set || !add_impl || !set_impl || !replace_impl || !remove_impl || !remove_all_impl || !contains_impl || !count_impl || !get_impl || !get_if_present_impl) {
        return 0;
    }

    CFStringRef alpha = create_str(0, "set-alpha", kCFStringEncodingUTF8);
    CFStringRef beta = create_str(0, "set-beta", kCFStringEncodingUTF8);
    CFStringRef beta_equivalent = create_str(0, "set-beta", kCFStringEncodingUTF8);
    CFStringRef gamma = create_str(0, "set-gamma", kCFStringEncodingUTF8);
    if (!alpha || !beta || !beta_equivalent || !gamma) {
        printf("compat cfset %s setup=0 pass=0\n", label);
        return 0;
    }

    const void *initial_values[3] = {alpha, beta, beta_equivalent};
    CFSetRef immutable = create_set(0, initial_values, 3, 0);
    CFIndex immutable_count = immutable ? count_impl(immutable) : -1;
    int immutable_contains = immutable ? contains_impl(immutable, beta_equivalent) : 0;

    CFMutableSetRef set = create_mutable_set(0, 0, 0);
    if (!set) {
        printf("compat cfset %s mutable=0 pass=0\n", label);
        return 0;
    }

    add_impl(set, alpha);
    add_impl(set, beta);
    add_impl(set, beta_equivalent);
    CFIndex count_after_duplicate = count_impl(set);
    int contains_equiv = contains_impl(set, beta_equivalent);
    const void *stored_before = get_impl(set, beta_equivalent);
    const void *present_before = 0;
    int present_before_ok = get_if_present_impl(set, beta_equivalent, &present_before);

    replace_impl(set, beta_equivalent);
    const void *stored_after_replace = get_impl(set, beta);
    set_impl(set, gamma);
    CFIndex count_after_set = count_impl(set);
    remove_impl(set, alpha);
    CFIndex count_after_remove = count_impl(set);
    remove_all_impl(set);
    CFIndex count_after_clear = count_impl(set);

    int ok = immutable_count == 2
        && immutable_contains
        && count_after_duplicate == 2
        && contains_equiv
        && stored_before == beta
        && present_before_ok
        && present_before == beta
        && stored_after_replace == beta_equivalent
        && count_after_set == 3
        && count_after_remove == 2
        && count_after_clear == 0;
    printf(
        "compat cfset %s immutable_count=%ld immutable_contains=%d duplicate_count=%ld contains=%d get_before=%d present=%d replaced=%d after_set=%ld after_remove=%ld empty=%ld pass=%d\n",
        label,
        (long)immutable_count,
        immutable_contains,
        (long)count_after_duplicate,
        contains_equiv,
        stored_before == beta,
        present_before_ok && present_before == beta,
        stored_after_replace == beta_equivalent,
        (long)count_after_set,
        (long)count_after_remove,
        (long)count_after_clear,
        ok
    );
    return ok ? 1 : 0;
}

static int exercise_iokit(
    const char *label,
    io_service_matching_fn matching_impl,
    io_service_get_matching_service_fn get_service_impl,
    io_registry_entry_get_name_fn get_name_impl,
    io_registry_entry_get_path_fn get_path_impl,
    io_registry_entry_get_registry_entry_id_fn get_id_impl,
    io_registry_entry_create_cf_property_fn property_impl,
    io_object_release_fn release_impl
) {
    CFMutableDictionaryRef matching = matching_impl ? matching_impl("IOPlatformExpertDevice") : 0;
    io_service_t service = matching && get_service_impl ? get_service_impl(0, matching) : 0;
    io_name_t name = {0};
    io_string_t path = {0};
    uint64_t entry_id = 0;
    kern_return_t name_ret = service && get_name_impl ? get_name_impl(service, name) : -1;
    kern_return_t path_ret = service && get_path_impl ? get_path_impl(service, "IOService", path) : -1;
    kern_return_t id_ret = service && get_id_impl ? get_id_impl(service, &entry_id) : -1;

    CFStringRef uuid_key = CFStringCreateWithCString(0, "IOPlatformUUID", kCFStringEncodingUTF8);
    CFTypeRef uuid_value = service && property_impl && uuid_key ? property_impl(service, uuid_key, 0, 0) : 0;
    char uuid_text[128] = {0};
    int uuid_ok = uuid_value && CFGetTypeID(uuid_value) == CFStringGetTypeID()
        ? CFStringGetCString((CFStringRef)uuid_value, uuid_text, sizeof(uuid_text), kCFStringEncodingUTF8)
        : 0;
    if (uuid_value) {
        CFRelease(uuid_value);
    }
    if (uuid_key) {
        CFRelease(uuid_key);
    }

    kern_return_t release_ret = service && release_impl ? release_impl(service) : -1;
    int ok = service
        && name_ret == 0
        && name[0] != 0
        && path_ret == 0
        && path[0] != 0
        && id_ret == 0
        && entry_id != 0
        && release_ret == 0;
    printf(
        "compat iokit %s service=%p name_ret=%d name=%s path_ret=%d path=%s id_ret=%d id=%llu uuid=%d uuid_text=%s release=%d pass=%d\n",
        label,
        (void *)(uintptr_t)service,
        name_ret,
        name,
        path_ret,
        path,
        id_ret,
        (unsigned long long)entry_id,
        uuid_ok,
        uuid_text,
        release_ret,
        ok
    );
    return ok ? 1 : 0;
}

int main(void) {
    char static_buf[64] = {0};
    CFStringRef s = CFStringCreateWithCString(0, "static-cf", kCFStringEncodingUTF8);
    Boolean s_ok = s ? CFStringGetCString(s, static_buf, sizeof(static_buf), kCFStringEncodingUTF8) : 0;
    CFIndex s_len = s ? CFStringGetLength(s) : -1;
    CFDataRef data = CFDataCreate(0, (const UInt8 *)"cfdata", 6);
    CFIndex data_len = data ? CFDataGetLength(data) : -1;
    const UInt8 *data_ptr = data ? CFDataGetBytePtr(data) : 0;
    CFTypeID string_type = CFStringGetTypeID();
    CFTypeID data_type = CFDataGetTypeID();
    CFTypeID static_string_type = s ? CFGetTypeID(s) : 0;
    CFTypeID static_data_type = data ? CFGetTypeID(data) : 0;
    int type_ok = string_type != 0 && data_type != 0 && static_string_type == string_type && static_data_type == data_type;
    unsigned char rnd[16] = {0};
    int rnd_ret = SecRandomCopyBytes(0, sizeof(rnd), rnd);
    CFStringRef err = SecCopyErrorMessageString(-50, 0);
    char err_buf[128] = {0};
    Boolean err_ok = err ? CFStringGetCString(err, err_buf, sizeof(err_buf), kCFStringEncodingUTF8) : 0;
    int data_ok = data_len == 6 && data_ptr && memcmp(data_ptr, "cfdata", 6) == 0;
    int static_array_ok = exercise_cfarray(
        "static",
        CFStringCreateWithCString,
        CFArrayCreateMutable,
        CFArrayAppendValue,
        CFArrayInsertValueAtIndex,
        CFArraySetValueAtIndex,
        CFArrayRemoveValueAtIndex,
        CFArrayRemoveAllValues,
        CFArrayContainsValue,
        CFArrayGetCount,
        CFArrayGetValueAtIndex
    );
    int static_set_ok = exercise_cfset(
        "static",
        CFStringCreateWithCString,
        CFSetCreate,
        CFSetCreateMutable,
        CFSetAddValue,
        CFSetSetValue,
        CFSetReplaceValue,
        CFSetRemoveValue,
        CFSetRemoveAllValues,
        CFSetContainsValue,
        CFSetGetCount,
        CFSetGetValue,
        CFSetGetValueIfPresent
    );
    int static_url_ok = exercise_cfurl(
        "static",
        CFStringCreateWithCString,
        CFStringGetCString,
        CFURLCreateWithString,
        CFURLGetString
    );
    int static_ok = s_ok && s_len == 9 && strcmp(static_buf, "static-cf") == 0 && data_ok && type_ok && rnd_ret == 0 && any_nonzero(rnd, sizeof(rnd)) && err_ok && static_array_ok && static_set_ok && static_url_ok;
    printf(
        "compat apple static cf ok=%d len=%ld text=%s data_len=%ld data_text=%.*s type_ok=%d string_type=%lu data_type=%lu random=%d nonzero=%d err=%d errtext=%s pass=%d\n",
        s_ok,
        (long)s_len,
        static_buf,
        (long)data_len,
        (int)(data_len > 0 && data_len < 64 ? data_len : 0),
        data_ptr ? (const char *)data_ptr : "",
        type_ok,
        (unsigned long)string_type,
        (unsigned long)data_type,
        rnd_ret,
        any_nonzero(rnd, sizeof(rnd)),
        err_ok,
        err_buf,
        static_ok
    );

    char static_sec_class_text[32] = {0};
    char static_sec_value_text[32] = {0};
    int static_sec_constants_ok = CFStringGetCString(kSecClass, static_sec_class_text, sizeof(static_sec_class_text), kCFStringEncodingUTF8)
        && CFStringGetCString(kSecValueData, static_sec_value_text, sizeof(static_sec_value_text), kCFStringEncodingUTF8)
        && strcmp(static_sec_class_text, "class") == 0
        && strcmp(static_sec_value_text, "v_Data") == 0;
    CFDictionaryRef static_lookup_query = make_secitem_query("compatra-ci-secitem-static", "bridge-static", 0);
    const void *static_lookup_class = static_lookup_query ? CFDictionaryGetValue(static_lookup_query, kSecClass) : 0;
    int static_secitem_bridge_ok = static_lookup_query && static_lookup_class == kSecClassGenericPassword;
    int static_mut_delete_ops_ok = 0;
    int static_mut_add_ops_ok = 0;
    CFMutableDictionaryRef static_mut_lookup_query = make_secitem_mutable_query("compatra-ci-secitem-mutable-static", "bridge-mut-static", 0, &static_mut_delete_ops_ok);
    CFMutableDictionaryRef static_mut_value_query = make_secitem_mutable_query("compatra-ci-secitem-mutable-static", "bridge-mut-static", 1, &static_mut_add_ops_ok);
    const void *static_mut_class = static_mut_lookup_query ? CFDictionaryGetValue(static_mut_lookup_query, kSecClass) : 0;
    const void *static_mut_value_data = static_mut_value_query ? CFDictionaryGetValue(static_mut_value_query, kSecValueData) : 0;
    int static_mut_ops_ok = static_mut_delete_ops_ok && static_mut_add_ops_ok;
    int static_mut_secitem_bridge_ok = static_mut_lookup_query && static_mut_value_query && static_mut_ops_ok && static_mut_class == kSecClassGenericPassword && static_mut_value_data;
    int static_security_ok = static_sec_constants_ok && static_secitem_bridge_ok && static_mut_secitem_bridge_ok;
    printf(
        "compat security static keychain_calls=skipped const=%d pass=%d\n",
        static_sec_constants_ok,
        static_security_ok
    );
    printf(
        "compat security-search static skipped=1 reason=ci-noninteractive-keychain pass=%d\n",
        static_security_ok
    );
    printf(
        "compat security-secitem static const=%d class=%s value=%s lookup_query=%p class_value=%p bridge=%d pass=%d\n",
        static_sec_constants_ok,
        static_sec_class_text,
        static_sec_value_text,
        (void *)static_lookup_query,
        static_lookup_class,
        static_secitem_bridge_ok,
        static_security_ok
    );
    printf(
        "compat security-secitem-mutable static ops=%d lookup_query=%p value_query=%p class_value=%p value_data=%p bridge=%d pass=%d\n",
        static_mut_ops_ok,
        (void *)static_mut_lookup_query,
        (void *)static_mut_value_query,
        static_mut_class,
        static_mut_value_data,
        static_mut_secitem_bridge_ok,
        static_security_ok
    );

    int static_iokit_ok = exercise_iokit(
        "static",
        IOServiceMatching,
        IOServiceGetMatchingService,
        IORegistryEntryGetName,
        IORegistryEntryGetPath,
        IORegistryEntryGetRegistryEntryID,
        IORegistryEntryCreateCFProperty,
        IOObjectRelease
    );

    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    cf_create_cstr_fn dyn_create = (cf_create_cstr_fn)dlsym(cf, "CFStringCreateWithCString");
    cf_get_cstr_fn dyn_get = (cf_get_cstr_fn)dlsym(cf, "CFStringGetCString");
    cf_get_len_fn dyn_len = (cf_get_len_fn)dlsym(cf, "CFStringGetLength");
    cf_data_create_fn dyn_data_create = (cf_data_create_fn)dlsym(cf, "CFDataCreate");
    cf_data_get_len_fn dyn_data_len = (cf_data_get_len_fn)dlsym(cf, "CFDataGetLength");
    cf_data_get_bytes_fn dyn_data_bytes = (cf_data_get_bytes_fn)dlsym(cf, "CFDataGetBytePtr");
    cf_get_type_id_fn dyn_get_type = (cf_get_type_id_fn)dlsym(cf, "CFGetTypeID");
    cf_type_id_fn dyn_string_type = (cf_type_id_fn)dlsym(cf, "CFStringGetTypeID");
    cf_type_id_fn dyn_data_type = (cf_type_id_fn)dlsym(cf, "CFDataGetTypeID");
    cf_url_create_string_fn dyn_url_create_string = (cf_url_create_string_fn)dlsym(cf, "CFURLCreateWithString");
    cf_url_get_string_fn dyn_url_get_string = (cf_url_get_string_fn)dlsym(cf, "CFURLGetString");
    cf_array_create_mutable_fn dyn_array_create_mutable = (cf_array_create_mutable_fn)dlsym(cf, "CFArrayCreateMutable");
    cf_array_mutate_fn dyn_array_append = (cf_array_mutate_fn)dlsym(cf, "CFArrayAppendValue");
    cf_array_index_mutate_fn dyn_array_insert = (cf_array_index_mutate_fn)dlsym(cf, "CFArrayInsertValueAtIndex");
    cf_array_index_mutate_fn dyn_array_set = (cf_array_index_mutate_fn)dlsym(cf, "CFArraySetValueAtIndex");
    cf_array_remove_fn dyn_array_remove = (cf_array_remove_fn)dlsym(cf, "CFArrayRemoveValueAtIndex");
    cf_array_remove_all_fn dyn_array_remove_all = (cf_array_remove_all_fn)dlsym(cf, "CFArrayRemoveAllValues");
    cf_array_contains_fn dyn_array_contains = (cf_array_contains_fn)dlsym(cf, "CFArrayContainsValue");
    cf_array_get_count_fn dyn_array_count = (cf_array_get_count_fn)dlsym(cf, "CFArrayGetCount");
    cf_array_get_value_fn dyn_array_get = (cf_array_get_value_fn)dlsym(cf, "CFArrayGetValueAtIndex");
    cf_set_create_fn dyn_set_create = (cf_set_create_fn)dlsym(cf, "CFSetCreate");
    cf_set_create_mutable_fn dyn_set_create_mutable = (cf_set_create_mutable_fn)dlsym(cf, "CFSetCreateMutable");
    cf_set_mutate_fn dyn_set_add = (cf_set_mutate_fn)dlsym(cf, "CFSetAddValue");
    cf_set_mutate_fn dyn_set_set = (cf_set_mutate_fn)dlsym(cf, "CFSetSetValue");
    cf_set_mutate_fn dyn_set_replace = (cf_set_mutate_fn)dlsym(cf, "CFSetReplaceValue");
    cf_set_mutate_fn dyn_set_remove = (cf_set_mutate_fn)dlsym(cf, "CFSetRemoveValue");
    cf_set_remove_all_fn dyn_set_remove_all = (cf_set_remove_all_fn)dlsym(cf, "CFSetRemoveAllValues");
    cf_set_contains_fn dyn_set_contains = (cf_set_contains_fn)dlsym(cf, "CFSetContainsValue");
    cf_set_get_count_fn dyn_set_count = (cf_set_get_count_fn)dlsym(cf, "CFSetGetCount");
    cf_set_get_value_fn dyn_set_get = (cf_set_get_value_fn)dlsym(cf, "CFSetGetValue");
    cf_set_get_value_if_present_fn dyn_set_get_if_present = (cf_set_get_value_if_present_fn)dlsym(cf, "CFSetGetValueIfPresent");
    cf_dictionary_create_mutable_fn dyn_dict_create_mutable = (cf_dictionary_create_mutable_fn)dlsym(cf, "CFDictionaryCreateMutable");
    cf_dictionary_mutate_fn dyn_dict_set = (cf_dictionary_mutate_fn)dlsym(cf, "CFDictionarySetValue");
    cf_dictionary_mutate_fn dyn_dict_add = (cf_dictionary_mutate_fn)dlsym(cf, "CFDictionaryAddValue");
    cf_dictionary_mutate_fn dyn_dict_replace = (cf_dictionary_mutate_fn)dlsym(cf, "CFDictionaryReplaceValue");
    cf_dictionary_remove_fn dyn_dict_remove = (cf_dictionary_remove_fn)dlsym(cf, "CFDictionaryRemoveValue");
    cf_dictionary_remove_all_fn dyn_dict_remove_all = (cf_dictionary_remove_all_fn)dlsym(cf, "CFDictionaryRemoveAllValues");
    cf_dictionary_get_value_fn dyn_dict_get = (cf_dictionary_get_value_fn)dlsym(cf, "CFDictionaryGetValue");
    cf_dictionary_get_count_fn dyn_dict_count = (cf_dictionary_get_count_fn)dlsym(cf, "CFDictionaryGetCount");
    sec_random_fn dyn_random = (sec_random_fn)dlsym(sec, "SecRandomCopyBytes");
    sec_error_fn dyn_error = (sec_error_fn)dlsym(sec, "SecCopyErrorMessageString");
    sec_item_copy_matching_fn dyn_item_copy = (sec_item_copy_matching_fn)dlsym(sec, "SecItemCopyMatching");
    sec_item_add_fn dyn_item_add = (sec_item_add_fn)dlsym(sec, "SecItemAdd");
    sec_item_delete_fn dyn_item_delete = (sec_item_delete_fn)dlsym(sec, "SecItemDelete");
    sec_keychain_copy_default_fn dyn_keychain_default = (sec_keychain_copy_default_fn)dlsym(sec, "SecKeychainCopyDefault");
    sec_keychain_open_fn dyn_keychain_open = (sec_keychain_open_fn)dlsym(sec, "SecKeychainOpen");
    sec_keychain_get_path_fn dyn_keychain_path = (sec_keychain_get_path_fn)dlsym(sec, "SecKeychainGetPath");
    sec_keychain_find_generic_password_fn dyn_keychain_find = (sec_keychain_find_generic_password_fn)dlsym(sec, "SecKeychainFindGenericPassword");
    sec_keychain_search_create_fn dyn_keychain_search_create = (sec_keychain_search_create_fn)dlsym(sec, "SecKeychainSearchCreateFromAttributes");
    sec_keychain_search_next_fn dyn_keychain_search_next = (sec_keychain_search_next_fn)dlsym(sec, "SecKeychainSearchCopyNext");
    sec_keychain_item_copy_content_fn dyn_keychain_content = (sec_keychain_item_copy_content_fn)dlsym(sec, "SecKeychainItemCopyContent");
    sec_keychain_item_free_content_fn dyn_keychain_free = (sec_keychain_item_free_content_fn)dlsym(sec, "SecKeychainItemFreeContent");
    io_service_matching_fn dyn_io_matching = (io_service_matching_fn)dlsym(iokit, "IOServiceMatching");
    io_service_get_matching_service_fn dyn_io_get_service = (io_service_get_matching_service_fn)dlsym(iokit, "IOServiceGetMatchingService");
    io_registry_entry_get_name_fn dyn_io_get_name = (io_registry_entry_get_name_fn)dlsym(iokit, "IORegistryEntryGetName");
    io_registry_entry_get_path_fn dyn_io_get_path = (io_registry_entry_get_path_fn)dlsym(iokit, "IORegistryEntryGetPath");
    io_registry_entry_get_registry_entry_id_fn dyn_io_get_id = (io_registry_entry_get_registry_entry_id_fn)dlsym(iokit, "IORegistryEntryGetRegistryEntryID");
    io_registry_entry_create_cf_property_fn dyn_io_property = (io_registry_entry_create_cf_property_fn)dlsym(iokit, "IORegistryEntryCreateCFProperty");
    io_object_release_fn dyn_io_release = (io_object_release_fn)dlsym(iokit, "IOObjectRelease");
    printf(
        "compat apple dlsym ptrs create=%p get=%p len=%p data_create=%p data_len=%p data_bytes=%p get_type=%p string_type=%p data_type=%p url_create_string=%p url_get_string=%p array_mut=%p array_append=%p array_insert=%p array_set=%p array_remove=%p array_remove_all=%p array_contains=%p array_count=%p array_get=%p set_create=%p set_mut=%p set_add=%p set_set=%p set_replace=%p set_remove=%p set_remove_all=%p set_contains=%p set_count=%p set_get=%p set_get_present=%p dict_mut=%p dict_set=%p dict_add=%p dict_replace=%p dict_remove=%p dict_remove_all=%p dict_get=%p dict_count=%p random=%p error=%p item_copy=%p item_add=%p item_delete=%p kc_default=%p kc_open=%p kc_path=%p kc_find=%p kc_search_create=%p kc_search_next=%p kc_content=%p kc_free=%p\n",
        (void *)dyn_create,
        (void *)dyn_get,
        (void *)dyn_len,
        (void *)dyn_data_create,
        (void *)dyn_data_len,
        (void *)dyn_data_bytes,
        (void *)dyn_get_type,
        (void *)dyn_string_type,
        (void *)dyn_data_type,
        (void *)dyn_url_create_string,
        (void *)dyn_url_get_string,
        (void *)dyn_array_create_mutable,
        (void *)dyn_array_append,
        (void *)dyn_array_insert,
        (void *)dyn_array_set,
        (void *)dyn_array_remove,
        (void *)dyn_array_remove_all,
        (void *)dyn_array_contains,
        (void *)dyn_array_count,
        (void *)dyn_array_get,
        (void *)dyn_set_create,
        (void *)dyn_set_create_mutable,
        (void *)dyn_set_add,
        (void *)dyn_set_set,
        (void *)dyn_set_replace,
        (void *)dyn_set_remove,
        (void *)dyn_set_remove_all,
        (void *)dyn_set_contains,
        (void *)dyn_set_count,
        (void *)dyn_set_get,
        (void *)dyn_set_get_if_present,
        (void *)dyn_dict_create_mutable,
        (void *)dyn_dict_set,
        (void *)dyn_dict_add,
        (void *)dyn_dict_replace,
        (void *)dyn_dict_remove,
        (void *)dyn_dict_remove_all,
        (void *)dyn_dict_get,
        (void *)dyn_dict_count,
        (void *)dyn_random,
        (void *)dyn_error,
        (void *)dyn_item_copy,
        (void *)dyn_item_add,
        (void *)dyn_item_delete,
        (void *)dyn_keychain_default,
        (void *)dyn_keychain_open,
        (void *)dyn_keychain_path,
        (void *)dyn_keychain_find,
        (void *)dyn_keychain_search_create,
        (void *)dyn_keychain_search_next,
        (void *)dyn_keychain_content,
        (void *)dyn_keychain_free
    );
    printf(
        "compat iokit dlsym ptrs matching=%p get_service=%p get_name=%p get_path=%p get_id=%p property=%p release=%p\n",
        (void *)dyn_io_matching,
        (void *)dyn_io_get_service,
        (void *)dyn_io_get_name,
        (void *)dyn_io_get_path,
        (void *)dyn_io_get_id,
        (void *)dyn_io_property,
        (void *)dyn_io_release
    );

    char dyn_buf[64] = {0};
    CFStringRef ds = dyn_create ? dyn_create(0, "dyn-cf", kCFStringEncodingUTF8) : 0;
    Boolean d_ok = dyn_get && ds ? dyn_get(ds, dyn_buf, sizeof(dyn_buf), kCFStringEncodingUTF8) : 0;
    CFIndex d_len = dyn_len && ds ? dyn_len(ds) : -1;
    CFDataRef ddata = dyn_data_create ? dyn_data_create(0, (const UInt8 *)"dyndata", 7) : 0;
    CFIndex ddata_len = dyn_data_len && ddata ? dyn_data_len(ddata) : -1;
    const UInt8 *ddata_ptr = dyn_data_bytes && ddata ? dyn_data_bytes(ddata) : 0;
    CFTypeID d_string_type = dyn_string_type ? dyn_string_type() : 0;
    CFTypeID d_data_type = dyn_data_type ? dyn_data_type() : 0;
    CFTypeID d_string_obj_type = dyn_get_type && ds ? dyn_get_type(ds) : 0;
    CFTypeID d_data_obj_type = dyn_get_type && ddata ? dyn_get_type(ddata) : 0;
    int d_type_ok = d_string_type != 0 && d_data_type != 0 && d_string_obj_type == d_string_type && d_data_obj_type == d_data_type;
    int d_data_ok = ddata_len == 7 && ddata_ptr && memcmp(ddata_ptr, "dyndata", 7) == 0;
    int dyn_array_ok = exercise_cfarray(
        "dlsym",
        dyn_create,
        dyn_array_create_mutable,
        dyn_array_append,
        dyn_array_insert,
        dyn_array_set,
        dyn_array_remove,
        dyn_array_remove_all,
        dyn_array_contains,
        dyn_array_count,
        dyn_array_get
    );
    int dyn_set_ok = exercise_cfset(
        "dlsym",
        dyn_create,
        dyn_set_create,
        dyn_set_create_mutable,
        dyn_set_add,
        dyn_set_set,
        dyn_set_replace,
        dyn_set_remove,
        dyn_set_remove_all,
        dyn_set_contains,
        dyn_set_count,
        dyn_set_get,
        dyn_set_get_if_present
    );
    int dyn_url_ok = exercise_cfurl(
        "dlsym",
        dyn_create,
        dyn_get,
        dyn_url_create_string,
        dyn_url_get_string
    );
    unsigned char dyn_rnd[16] = {0};
    int dyn_rnd_ret = dyn_random ? dyn_random(0, sizeof(dyn_rnd), dyn_rnd) : -1;
    CFStringRef derr = dyn_error ? dyn_error(-50, 0) : 0;
    char derr_buf[128] = {0};
    Boolean derr_ok = dyn_get && derr ? dyn_get(derr, derr_buf, sizeof(derr_buf), kCFStringEncodingUTF8) : 0;
    int dyn_ok = d_ok && d_len == 6 && strcmp(dyn_buf, "dyn-cf") == 0 && d_data_ok && d_type_ok && dyn_array_ok && dyn_set_ok && dyn_url_ok && dyn_rnd_ret == 0 && any_nonzero(dyn_rnd, sizeof(dyn_rnd)) && derr_ok;
    printf(
        "compat apple dlsym cf ok=%d len=%ld text=%s data_len=%ld data_text=%.*s type_ok=%d string_type=%lu data_type=%lu random=%d nonzero=%d err=%d errtext=%s pass=%d\n",
        d_ok,
        (long)d_len,
        dyn_buf,
        (long)ddata_len,
        (int)(ddata_len > 0 && ddata_len < 64 ? ddata_len : 0),
        ddata_ptr ? (const char *)ddata_ptr : "",
        d_type_ok,
        (unsigned long)d_string_type,
        (unsigned long)d_data_type,
        dyn_rnd_ret,
        any_nonzero(dyn_rnd, sizeof(dyn_rnd)),
        derr_ok,
        derr_buf,
        dyn_ok
    );

    char dyn_sec_class_text[32] = {0};
    char dyn_sec_value_text[32] = {0};
    int dyn_sec_constants_ok = dyn_get
        && dyn_get(kSecClass, dyn_sec_class_text, sizeof(dyn_sec_class_text), kCFStringEncodingUTF8)
        && dyn_get(kSecValueData, dyn_sec_value_text, sizeof(dyn_sec_value_text), kCFStringEncodingUTF8)
        && strcmp(dyn_sec_class_text, "class") == 0
        && strcmp(dyn_sec_value_text, "v_Data") == 0;
    CFDictionaryRef dyn_lookup_query = make_secitem_query("compatra-ci-secitem-dynamic", "bridge-dynamic", 0);
    const void *dyn_lookup_class = dyn_dict_get && dyn_lookup_query ? dyn_dict_get(dyn_lookup_query, kSecClass) : 0;
    int dyn_secitem_bridge_ok = dyn_item_copy && dyn_lookup_query && dyn_lookup_class == kSecClassGenericPassword;
    int dyn_mut_delete_ops_ok = 0;
    int dyn_mut_add_ops_ok = 0;
    CFMutableDictionaryRef dyn_mut_lookup_query = make_secitem_mutable_query_with(
        "compatra-ci-secitem-mutable-dynamic",
        "bridge-mut-dynamic",
        0,
        dyn_dict_create_mutable,
        dyn_dict_set,
        dyn_dict_add,
        dyn_dict_replace,
        dyn_dict_remove,
        dyn_dict_remove_all,
        dyn_dict_get,
        dyn_dict_count,
        &dyn_mut_delete_ops_ok
    );
    CFMutableDictionaryRef dyn_mut_value_query = make_secitem_mutable_query_with(
        "compatra-ci-secitem-mutable-dynamic",
        "bridge-mut-dynamic",
        1,
        dyn_dict_create_mutable,
        dyn_dict_set,
        dyn_dict_add,
        dyn_dict_replace,
        dyn_dict_remove,
        dyn_dict_remove_all,
        dyn_dict_get,
        dyn_dict_count,
        &dyn_mut_add_ops_ok
    );
    const void *dyn_mut_class = dyn_dict_get && dyn_mut_lookup_query ? dyn_dict_get(dyn_mut_lookup_query, kSecClass) : 0;
    const void *dyn_mut_value_data = dyn_dict_get && dyn_mut_value_query ? dyn_dict_get(dyn_mut_value_query, kSecValueData) : 0;
    int dyn_mut_ops_ok = dyn_mut_delete_ops_ok && dyn_mut_add_ops_ok;
    int dyn_mut_secitem_bridge_ok = dyn_item_copy && dyn_mut_lookup_query && dyn_mut_value_query && dyn_mut_ops_ok && dyn_mut_class == kSecClassGenericPassword && dyn_mut_value_data;
    int dyn_security_ok = dyn_item_copy && dyn_item_add && dyn_item_delete && dyn_keychain_default && dyn_keychain_open && dyn_keychain_path && dyn_keychain_find && dyn_keychain_search_create && dyn_keychain_search_next && dyn_keychain_content && dyn_keychain_free && dyn_sec_constants_ok && dyn_secitem_bridge_ok && dyn_mut_secitem_bridge_ok;
    printf(
        "compat security dlsym keychain_calls=skipped const=%d item_copy=%p item_add=%p item_delete=%p kc_default=%p kc_open=%p kc_path=%p kc_find=%p kc_search_create=%p kc_search_next=%p kc_content=%p kc_free=%p pass=%d\n",
        dyn_sec_constants_ok,
        (void *)dyn_item_copy,
        (void *)dyn_item_add,
        (void *)dyn_item_delete,
        (void *)dyn_keychain_default,
        (void *)dyn_keychain_open,
        (void *)dyn_keychain_path,
        (void *)dyn_keychain_find,
        (void *)dyn_keychain_search_create,
        (void *)dyn_keychain_search_next,
        (void *)dyn_keychain_content,
        (void *)dyn_keychain_free,
        dyn_security_ok
    );
    printf(
        "compat security-search dlsym skipped=1 reason=ci-noninteractive-keychain pass=%d\n",
        dyn_security_ok
    );
    printf(
        "compat security-secitem dlsym const=%d class=%s value=%s lookup_query=%p class_value=%p bridge=%d pass=%d\n",
        dyn_sec_constants_ok,
        dyn_sec_class_text,
        dyn_sec_value_text,
        (void *)dyn_lookup_query,
        dyn_lookup_class,
        dyn_secitem_bridge_ok,
        dyn_security_ok
    );
    printf(
        "compat security-secitem-mutable dlsym ops=%d lookup_query=%p value_query=%p class_value=%p value_data=%p bridge=%d pass=%d\n",
        dyn_mut_ops_ok,
        (void *)dyn_mut_lookup_query,
        (void *)dyn_mut_value_query,
        dyn_mut_class,
        dyn_mut_value_data,
        dyn_mut_secitem_bridge_ok,
        dyn_security_ok
    );

    int dyn_iokit_ok = dyn_io_matching
        && dyn_io_get_service
        && dyn_io_get_name
        && dyn_io_get_path
        && dyn_io_get_id
        && dyn_io_property
        && dyn_io_release
        && exercise_iokit(
            "dlsym",
            dyn_io_matching,
            dyn_io_get_service,
            dyn_io_get_name,
            dyn_io_get_path,
            dyn_io_get_id,
            dyn_io_property,
            dyn_io_release
        );

    return static_ok && dyn_ok && static_security_ok && dyn_security_ok && static_iokit_ok && dyn_iokit_ok ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 Apple framework fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-framework")
        .arg("CoreFoundation")
        .arg("-framework")
        .arg("Security")
        .arg("-framework")
        .arg("IOKit")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 Apple framework fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 Apple framework fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_foundation_startup_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_foundation_startup_compat.c");
    let binary = out_dir.join("arm64_foundation_startup_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

extern void *NSHomeDirectory(void);
extern void *NSTemporaryDirectory(void);
extern void *NSUserName(void);
extern void *NSSearchPathForDirectoriesInDomains(uintptr_t, uintptr_t, unsigned char);
extern void *NSSelectorFromString(void *);
extern void *NSStringFromSelector(void *);
extern void *objc_getClass(const char *);
extern void *sel_registerName(const char *);
extern uintptr_t objc_msgSend(void *, void *, ...);

typedef void *(*ns_string_noargs_fn)(void);
typedef void *(*ns_search_paths_fn)(uintptr_t, uintptr_t, unsigned char);
typedef void *(*ns_selector_from_string_fn)(void *);
typedef void *(*ns_string_from_selector_fn)(void *);

enum {
    NSDocumentDirectoryCompat = 9,
    NSCachesDirectoryCompat = 13,
    NSUserDomainMaskCompat = 1,
};

static void *cls(const char *name) {
    return objc_getClass(name);
}

static void *sel(const char *name) {
    return sel_registerName(name);
}

static void *msg0_obj(void *receiver, const char *selector) {
    return (void *)objc_msgSend(receiver, sel(selector));
}

static void *msg1_obj(void *receiver, const char *selector, void *arg0) {
    return (void *)objc_msgSend(receiver, sel(selector), arg0);
}

static void *msg2_obj(void *receiver, const char *selector, void *arg0, void *arg1) {
    return (void *)objc_msgSend(receiver, sel(selector), arg0, arg1);
}

static uintptr_t msg0_uint(void *receiver, const char *selector) {
    return objc_msgSend(receiver, sel(selector));
}

static uintptr_t msg2_uint(void *receiver, const char *selector, void *arg0, void *arg1) {
    return objc_msgSend(receiver, sel(selector), arg0, arg1);
}

static const char *utf8_or_null(void *value) {
    if (!value) {
        return "<null>";
    }
    const char *text = (const char *)objc_msgSend(value, sel("UTF8String"));
    return text ? text : "<null>";
}

static int has_text(void *value) {
    const char *text = utf8_or_null(value);
    return text && text[0] != 0 && strcmp(text, "<null>") != 0;
}

static void *ns_string(const char *text) {
    return msg1_obj(cls("NSString"), "stringWithUTF8String:", (void *)text);
}

int main(void) {
    void *home = NSHomeDirectory();
    void *temp = NSTemporaryDirectory();
    void *user = NSUserName();
    void *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectoryCompat, NSUserDomainMaskCompat, 1);
    uintptr_t path_count = msg0_uint(paths, "count");
    void *first_path = path_count ? msg1_obj(paths, "objectAtIndex:", 0) : 0;

    void *process = msg0_obj(cls("NSProcessInfo"), "processInfo");
    void *process_name = msg0_obj(process, "processName");
    void *arguments = msg0_obj(process, "arguments");
    void *environment = msg0_obj(process, "environment");
    void *home_key = ns_string("HOME");
    void *home_value = msg1_obj(environment, "objectForKey:", home_key);

    void *bundle = msg0_obj(cls("NSBundle"), "mainBundle");
    void *bundle_path = msg0_obj(bundle, "bundlePath");
    void *info = msg0_obj(bundle, "infoDictionary");
    void *bundle_key = ns_string("CFBundleExecutable");
    void *bundle_exe = msg1_obj(bundle, "objectForInfoDictionaryKey:", bundle_key);
    if (!bundle_exe) {
        bundle_exe = msg1_obj(info, "objectForKey:", bundle_key);
    }

    void *fm = msg0_obj(cls("NSFileManager"), "defaultManager");
    void *cwd = msg0_obj(fm, "currentDirectoryPath");
    unsigned char is_dir = 0;
    uintptr_t cwd_exists = msg2_uint(fm, "fileExistsAtPath:isDirectory:", cwd, &is_dir);
    void *cwd_entries = msg2_obj(fm, "contentsOfDirectoryAtPath:error:", cwd, 0);
    uintptr_t entry_count = msg0_uint(cwd_entries, "count");
    FILE *seed = fopen("foundation-data.txt", "w");
    if (seed) {
        fputs("foundation-data-ok", seed);
        fclose(seed);
    }
    void *data_path = ns_string("foundation-data.txt");
    void *data = msg1_obj(cls("NSData"), "dataWithContentsOfFile:", data_path);
    uintptr_t data_len = msg0_uint(data, "length");
    const char *data_bytes = data ? (const char *)msg0_obj(data, "bytes") : 0;
    void *out_path = ns_string("foundation-data-out.txt");
    uintptr_t data_write = data ? msg2_uint(data, "writeToFile:atomically:", out_path, (void *)1) : 0;
    void *data_roundtrip = msg1_obj(cls("NSData"), "dataWithContentsOfFile:", out_path);
    uintptr_t roundtrip_len = msg0_uint(data_roundtrip, "length");
    const char *roundtrip_bytes = data_roundtrip ? (const char *)msg0_obj(data_roundtrip, "bytes") : 0;
    mkdir("foundation-enum", 0700);
    mkdir("foundation-enum/sub", 0700);
    FILE *enum_file = fopen("foundation-enum/sub/item.txt", "w");
    if (enum_file) {
        fputs("enum", enum_file);
        fclose(enum_file);
    }
    void *enumerator = msg1_obj(fm, "enumeratorAtPath:", ns_string("foundation-enum"));
    void *enum_first = msg0_obj(enumerator, "nextObject");
    void *enum_second = msg0_obj(enumerator, "nextObject");
    void *enum_done_probe = msg0_obj(enumerator, "nextObject");

    int static_ok = has_text(home)
        && has_text(temp)
        && has_text(user)
        && path_count > 0
        && has_text(first_path)
        && has_text(process_name)
        && msg0_uint(arguments, "count") > 0
        && has_text(home_value)
        && has_text(bundle_path)
        && has_text(bundle_exe)
        && cwd_exists
        && is_dir
        && entry_count > 0
        && data_len == strlen("foundation-data-ok")
        && data_bytes
        && memcmp(data_bytes, "foundation-data-ok", strlen("foundation-data-ok")) == 0
        && data_write
        && roundtrip_len == strlen("foundation-data-ok")
        && roundtrip_bytes
        && memcmp(roundtrip_bytes, "foundation-data-ok", strlen("foundation-data-ok")) == 0
        && has_text(enum_first)
        && has_text(enum_second)
        && enum_done_probe == 0;

    printf(
        "compat foundation static home=%s temp=%s user=%s paths=%lu first=%s process=%s args=%lu env_home=%s bundle=%s exe=%s cwd=%s exists=%lu isdir=%u entries=%lu data_len=%lu write=%lu roundtrip=%lu enum_first=%s enum_second=%s enum_done_null=%lu pass=%d\n",
        utf8_or_null(home),
        utf8_or_null(temp),
        utf8_or_null(user),
        (unsigned long)path_count,
        utf8_or_null(first_path),
        utf8_or_null(process_name),
        (unsigned long)msg0_uint(arguments, "count"),
        utf8_or_null(home_value),
        utf8_or_null(bundle_path),
        utf8_or_null(bundle_exe),
        utf8_or_null(cwd),
        (unsigned long)cwd_exists,
        (unsigned int)is_dir,
        (unsigned long)entry_count,
        (unsigned long)data_len,
        (unsigned long)data_write,
        (unsigned long)roundtrip_len,
        utf8_or_null(enum_first),
        utf8_or_null(enum_second),
        (unsigned long)(enum_done_probe == 0),
        static_ok
    );

    void *foundation = dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOW);
    ns_string_noargs_fn dyn_home = (ns_string_noargs_fn)dlsym(foundation, "NSHomeDirectory");
    ns_string_noargs_fn dyn_temp = (ns_string_noargs_fn)dlsym(foundation, "NSTemporaryDirectory");
    ns_search_paths_fn dyn_paths = (ns_search_paths_fn)dlsym(foundation, "NSSearchPathForDirectoriesInDomains");
    ns_selector_from_string_fn dyn_selector = (ns_selector_from_string_fn)dlsym(foundation, "NSSelectorFromString");
    ns_string_from_selector_fn dyn_selector_name = (ns_string_from_selector_fn)dlsym(foundation, "NSStringFromSelector");

    void *dyn_home_value = dyn_home ? dyn_home() : 0;
    void *dyn_temp_value = dyn_temp ? dyn_temp() : 0;
    void *dyn_path_values = dyn_paths ? dyn_paths(NSCachesDirectoryCompat, NSUserDomainMaskCompat, 1) : 0;
    void *dyn_sel = dyn_selector ? dyn_selector(ns_string("processName")) : 0;
    void *dyn_sel_name = dyn_selector_name && dyn_sel ? dyn_selector_name(dyn_sel) : 0;
    int dyn_ok = dyn_home
        && dyn_temp
        && dyn_paths
        && dyn_selector
        && dyn_selector_name
        && has_text(dyn_home_value)
        && has_text(dyn_temp_value)
        && msg0_uint(dyn_path_values, "count") > 0
        && dyn_sel
        && strcmp(utf8_or_null(dyn_sel_name), "processName") == 0;

    printf(
        "compat foundation dlsym ptrs home=%p temp=%p paths=%p selector=%p selname=%p\n",
        (void *)dyn_home,
        (void *)dyn_temp,
        (void *)dyn_paths,
        (void *)dyn_selector,
        (void *)dyn_selector_name
    );
    printf(
        "compat foundation dlsym home=%s temp=%s paths=%lu sel=%s pass=%d\n",
        utf8_or_null(dyn_home_value),
        utf8_or_null(dyn_temp_value),
        dyn_path_values ? (unsigned long)msg0_uint(dyn_path_values, "count") : 0UL,
        utf8_or_null(dyn_sel_name),
        dyn_ok
    );
    return static_ok && dyn_ok ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 Foundation startup fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-framework")
        .arg("Foundation")
        .arg("-lobjc")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 Foundation startup fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 Foundation startup fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(target_os = "macos")]
fn compile_arm64_appkit_startup_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_appkit_startup_compat.c");
    let binary = out_dir.join("arm64_appkit_startup_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int NSApplicationLoad(void);
extern int NSApplicationMain(int, const char **);
extern uint32_t CGMainDisplayID(void);
extern size_t CGDisplayPixelsWide(uint32_t);
extern size_t CGDisplayPixelsHigh(uint32_t);
extern int CGDisplayIsActive(uint32_t);
extern int CGDisplayIsOnline(uint32_t);
extern int CGPreflightScreenCaptureAccess(void);
extern void *CGDisplayCreateImage(uint32_t);
extern size_t CGImageGetWidth(void *);
extern size_t CGImageGetHeight(void *);
extern size_t CGImageGetBitsPerPixel(void *);
extern size_t CGImageGetBytesPerRow(void *);
extern void *CGImageGetDataProvider(void *);
extern void CGImageRelease(void *);
extern void *CGDataProviderCopyData(void *);
extern int CGEventSourceKeyState(uint32_t, uint16_t);
extern int CGPreflightListenEventAccess(void);
extern int AXIsProcessTrusted(void);
extern int AXIsProcessTrustedWithOptions(void *);
extern long CFDataGetLength(void *);
extern void *objc_getClass(const char *);
extern void *sel_registerName(const char *);
extern uintptr_t objc_msgSend(void *, void *, ...);

typedef int (*ns_application_load_fn)(void);
typedef int (*ns_application_main_fn)(int, const char **);
typedef uint32_t (*cg_main_display_id_fn)(void);
typedef size_t (*cg_display_pixels_fn)(uint32_t);
typedef int (*cg_display_predicate_fn)(uint32_t);
typedef int (*cg_noarg_bool_fn)(void);
typedef void *(*cg_display_image_fn)(uint32_t);
typedef size_t (*cg_image_size_fn)(void *);
typedef void *(*cg_image_provider_fn)(void *);
typedef void (*cg_image_release_fn)(void *);
typedef void *(*cg_provider_copy_data_fn)(void *);
typedef int (*cg_key_state_fn)(uint32_t, uint16_t);
typedef int (*ax_options_fn)(void *);

static void *cls(const char *name) {
    return objc_getClass(name);
}

static void *sel(const char *name) {
    return sel_registerName(name);
}

static void *msg0_obj(void *receiver, const char *selector) {
    return (void *)objc_msgSend(receiver, sel(selector));
}

static void *msg1_obj(void *receiver, const char *selector, void *arg0) {
    return (void *)objc_msgSend(receiver, sel(selector), arg0);
}

static uintptr_t msg0_uint(void *receiver, const char *selector) {
    return objc_msgSend(receiver, sel(selector));
}

static uintptr_t msg1_uint(void *receiver, const char *selector, uintptr_t arg0) {
    return objc_msgSend(receiver, sel(selector), arg0);
}

static uintptr_t msg2_uint(void *receiver, const char *selector, void *arg0, void *arg1) {
    return objc_msgSend(receiver, sel(selector), arg0, arg1);
}

static const char *utf8_or_null(void *value) {
    if (!value) {
        return "<null>";
    }
    const char *text = (const char *)objc_msgSend(value, sel("UTF8String"));
    return text ? text : "<null>";
}

static int has_text(void *value) {
    const char *text = utf8_or_null(value);
    return text && text[0] != 0 && strcmp(text, "<null>") != 0;
}

static void *ns_string(const char *text) {
    return msg1_obj(cls("NSString"), "stringWithUTF8String:", (void *)text);
}

int main(void) {
    int load = NSApplicationLoad();
    void *app_class = cls("NSApplication");
    void *app = msg0_obj(app_class, "sharedApplication");
    uintptr_t set_policy = msg1_uint(app, "setActivationPolicy:", 1);
    uintptr_t policy = msg0_uint(app, "activationPolicy");
    uintptr_t running = msg0_uint(app, "isRunning");

    void *thread_class = cls("NSThread");
    void *main_thread = msg0_obj(thread_class, "mainThread");
    uintptr_t class_main = msg0_uint(thread_class, "isMainThread");
    uintptr_t object_main = msg0_uint(main_thread, "isMainThread");

    void *runloop = msg0_obj(cls("NSRunLoop"), "currentRunLoop");
    void *mode = ns_string("compat-ui-mode");
    void *date = msg0_obj(cls("NSDate"), "date");
    uintptr_t run_mode = msg2_uint(runloop, "runMode:beforeDate:", mode, date);

    void *screen = msg0_obj(cls("NSScreen"), "mainScreen");
    void *screens = msg0_obj(cls("NSScreen"), "screens");
    uintptr_t screen_count = msg0_uint(screens, "count");
    void *screen_name = msg0_obj(screen, "localizedName");

    void *window = msg0_obj(cls("NSWindow"), "alloc");
    window = msg0_obj(window, "init");
    msg1_uint(window, "setTitle:", (uintptr_t)ns_string("Compat UI"));
    void *window_title = msg0_obj(window, "title");
    msg1_uint(window, "orderFront:", 0);
    uintptr_t can_key = msg0_uint(window, "canBecomeKeyWindow");
    uintptr_t visible = msg0_uint(window, "isVisible");
    msg0_uint(window, "close");

    uint32_t display = CGMainDisplayID();
    size_t width = CGDisplayPixelsWide(display);
    size_t height = CGDisplayPixelsHigh(display);
    int active = CGDisplayIsActive(display);
    int online = CGDisplayIsOnline(display);
    int screen_preflight = CGPreflightScreenCaptureAccess();
    void *screen_image = CGDisplayCreateImage(display);
    size_t image_width = screen_image ? CGImageGetWidth(screen_image) : 0;
    size_t image_height = screen_image ? CGImageGetHeight(screen_image) : 0;
    size_t image_bpp = screen_image ? CGImageGetBitsPerPixel(screen_image) : 0;
    size_t image_row = screen_image ? CGImageGetBytesPerRow(screen_image) : 0;
    void *image_provider = screen_image ? CGImageGetDataProvider(screen_image) : 0;
    void *image_data = image_provider ? CGDataProviderCopyData(image_provider) : 0;
    long image_data_len = image_data ? CFDataGetLength(image_data) : 0;
    int key_state = CGEventSourceKeyState(0, 0);
    int listen_preflight = CGPreflightListenEventAccess();
    int ax_trusted = AXIsProcessTrusted();
    int ax_options = AXIsProcessTrustedWithOptions(0);
    if (screen_image) {
        CGImageRelease(screen_image);
    }

    void *audio_type = ns_string("soun");
    void *capture_device_class = cls("AVCaptureDevice");
    uintptr_t mic_auth = capture_device_class ? msg1_uint(capture_device_class, "authorizationStatusForMediaType:", (uintptr_t)audio_type) : 999;
    void *default_audio = capture_device_class ? msg1_obj(capture_device_class, "defaultDeviceWithMediaType:", audio_type) : 0;
    void *audio_name = default_audio ? msg0_obj(default_audio, "localizedName") : 0;
    uintptr_t audio_connected = default_audio ? msg0_uint(default_audio, "isConnected") : 0;
    int privacy_ok = (screen_preflight == 0 || screen_preflight == 1)
        && (!screen_image || (image_width > 0 && image_height > 0 && image_bpp > 0 && image_row > 0 && image_provider && image_data && image_data_len > 0))
        && (key_state == 0 || key_state == 1)
        && (listen_preflight == 0 || listen_preflight == 1)
        && (ax_trusted == 0 || ax_trusted == 1)
        && (ax_options == 0 || ax_options == 1)
        && capture_device_class
        && mic_auth <= 4;

    const char *main_argv[] = {"compat-ui", 0};
    int appmain = NSApplicationMain(1, main_argv);

    int static_ok = load
        && app
        && set_policy
        && policy <= 2
        && running == 0
        && main_thread
        && class_main
        && object_main
        && runloop
        && run_mode <= 1
        && screen
        && screen_count > 0
        && has_text(screen_name)
        && window
        && has_text(window_title)
        && can_key
        && visible
        && display != 0
        && width > 0
        && height > 0
        && (active == 0 || active == 1)
        && (online == 0 || online == 1)
        && privacy_ok
        && appmain == 0;

    printf(
        "compat appkit static load=%d app=%p set=%lu policy=%lu running=%lu main=%lu/%lu runloop=%p runmode=%lu screen=%p screens=%lu name=%s window=%p title=%s cankey=%lu visible=%lu display=%u size=%zux%zu active=%d online=%d appmain=%d pass=%d\n",
        load,
        app,
        (unsigned long)set_policy,
        (unsigned long)policy,
        (unsigned long)running,
        (unsigned long)class_main,
        (unsigned long)object_main,
        runloop,
        (unsigned long)run_mode,
        screen,
        (unsigned long)screen_count,
        utf8_or_null(screen_name),
        window,
        utf8_or_null(window_title),
        (unsigned long)can_key,
        (unsigned long)visible,
        display,
        width,
        height,
        active,
        online,
        appmain,
        static_ok
    );
    printf(
        "compat privacy static screen_access=%d image=%p image_size=%zux%zu bpp=%zu row=%zu provider=%p data=%p data_len=%ld key_a=%d listen_access=%d ax=%d axopt=%d avclass=%p mic_auth=%lu mic=%p mic_connected=%lu mic_name=%s pass=%d\n",
        screen_preflight,
        screen_image,
        image_width,
        image_height,
        image_bpp,
        image_row,
        image_provider,
        image_data,
        image_data_len,
        key_state,
        listen_preflight,
        ax_trusted,
        ax_options,
        capture_device_class,
        (unsigned long)mic_auth,
        default_audio,
        (unsigned long)audio_connected,
        utf8_or_null(audio_name),
        privacy_ok
    );

    void *appkit = dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", RTLD_NOW);
    void *cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW);
    void *appservices = dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", RTLD_NOW);
    void *avfoundation = dlopen("/System/Library/Frameworks/AVFoundation.framework/AVFoundation", RTLD_NOW);
    ns_application_load_fn dyn_load = (ns_application_load_fn)dlsym(appkit, "NSApplicationLoad");
    ns_application_main_fn dyn_main = (ns_application_main_fn)dlsym(appkit, "NSApplicationMain");
    cg_main_display_id_fn dyn_display = (cg_main_display_id_fn)dlsym(cg, "CGMainDisplayID");
    cg_display_pixels_fn dyn_width = (cg_display_pixels_fn)dlsym(cg, "CGDisplayPixelsWide");
    cg_display_pixels_fn dyn_height = (cg_display_pixels_fn)dlsym(cg, "CGDisplayPixelsHigh");
    cg_display_predicate_fn dyn_active = (cg_display_predicate_fn)dlsym(cg, "CGDisplayIsActive");
    cg_display_predicate_fn dyn_online = (cg_display_predicate_fn)dlsym(cg, "CGDisplayIsOnline");
    cg_noarg_bool_fn dyn_screen_preflight = (cg_noarg_bool_fn)dlsym(cg, "CGPreflightScreenCaptureAccess");
    cg_display_image_fn dyn_create_image = (cg_display_image_fn)dlsym(cg, "CGDisplayCreateImage");
    cg_image_size_fn dyn_image_width = (cg_image_size_fn)dlsym(cg, "CGImageGetWidth");
    cg_image_size_fn dyn_image_height = (cg_image_size_fn)dlsym(cg, "CGImageGetHeight");
    cg_image_size_fn dyn_image_bpp = (cg_image_size_fn)dlsym(cg, "CGImageGetBitsPerPixel");
    cg_image_size_fn dyn_image_row = (cg_image_size_fn)dlsym(cg, "CGImageGetBytesPerRow");
    cg_image_provider_fn dyn_image_provider = (cg_image_provider_fn)dlsym(cg, "CGImageGetDataProvider");
    cg_image_release_fn dyn_image_release = (cg_image_release_fn)dlsym(cg, "CGImageRelease");
    cg_provider_copy_data_fn dyn_provider_data = (cg_provider_copy_data_fn)dlsym(cg, "CGDataProviderCopyData");
    cg_key_state_fn dyn_key_state = (cg_key_state_fn)dlsym(cg, "CGEventSourceKeyState");
    cg_noarg_bool_fn dyn_listen_preflight = (cg_noarg_bool_fn)dlsym(cg, "CGPreflightListenEventAccess");
    cg_noarg_bool_fn dyn_ax = (cg_noarg_bool_fn)dlsym(appservices, "AXIsProcessTrusted");
    ax_options_fn dyn_ax_options = (ax_options_fn)dlsym(appservices, "AXIsProcessTrustedWithOptions");

    uint32_t dyn_did = dyn_display ? dyn_display() : 0;
    size_t dyn_w = dyn_width ? dyn_width(dyn_did) : 0;
    size_t dyn_h = dyn_height ? dyn_height(dyn_did) : 0;
    int dyn_screen_access = dyn_screen_preflight ? dyn_screen_preflight() : -1;
    void *dyn_image = dyn_create_image ? dyn_create_image(dyn_did) : 0;
    size_t dyn_image_w = dyn_image && dyn_image_width ? dyn_image_width(dyn_image) : 0;
    size_t dyn_image_h = dyn_image && dyn_image_height ? dyn_image_height(dyn_image) : 0;
    size_t dyn_image_bits = dyn_image && dyn_image_bpp ? dyn_image_bpp(dyn_image) : 0;
    size_t dyn_image_stride = dyn_image && dyn_image_row ? dyn_image_row(dyn_image) : 0;
    void *dyn_provider = dyn_image && dyn_image_provider ? dyn_image_provider(dyn_image) : 0;
    void *dyn_pixels = dyn_provider && dyn_provider_data ? dyn_provider_data(dyn_provider) : 0;
    long dyn_pixels_len = dyn_pixels ? CFDataGetLength(dyn_pixels) : 0;
    int dyn_key_a = dyn_key_state ? dyn_key_state(0, 0) : -1;
    int dyn_listen_access = dyn_listen_preflight ? dyn_listen_preflight() : -1;
    int dyn_ax_trusted = dyn_ax ? dyn_ax() : -1;
    int dyn_ax_trusted_options = dyn_ax_options ? dyn_ax_options(0) : -1;
    if (dyn_image && dyn_image_release) {
        dyn_image_release(dyn_image);
    }
    int dyn_load_ret = dyn_load ? dyn_load() : 0;
    int dyn_main_ret = dyn_main ? dyn_main(1, main_argv) : -1;
    void *dyn_capture_device_class = cls("AVCaptureDevice");
    uintptr_t dyn_mic_auth = dyn_capture_device_class ? msg1_uint(dyn_capture_device_class, "authorizationStatusForMediaType:", (uintptr_t)audio_type) : 999;
    void *dyn_default_audio = dyn_capture_device_class ? msg1_obj(dyn_capture_device_class, "defaultDeviceWithMediaType:", audio_type) : 0;
    void *dyn_audio_name = dyn_default_audio ? msg0_obj(dyn_default_audio, "localizedName") : 0;
    int dyn_privacy_ok = dyn_screen_preflight
        && dyn_create_image
        && dyn_image_width
        && dyn_image_height
        && dyn_image_bpp
        && dyn_image_row
        && dyn_image_provider
        && dyn_image_release
        && dyn_provider_data
        && dyn_key_state
        && dyn_listen_preflight
        && dyn_ax
        && dyn_ax_options
        && (dyn_screen_access == 0 || dyn_screen_access == 1)
        && (!dyn_image || (dyn_image_w > 0 && dyn_image_h > 0 && dyn_image_bits > 0 && dyn_image_stride > 0 && dyn_provider && dyn_pixels && dyn_pixels_len > 0))
        && (dyn_key_a == 0 || dyn_key_a == 1)
        && (dyn_listen_access == 0 || dyn_listen_access == 1)
        && (dyn_ax_trusted == 0 || dyn_ax_trusted == 1)
        && (dyn_ax_trusted_options == 0 || dyn_ax_trusted_options == 1)
        && avfoundation
        && dyn_capture_device_class
        && dyn_mic_auth <= 4;
    int dyn_ok = dyn_load
        && dyn_main
        && dyn_display
        && dyn_width
        && dyn_height
        && dyn_active
        && dyn_online
        && dyn_load_ret
        && dyn_main_ret == 0
        && dyn_did != 0
        && dyn_w > 0
        && dyn_h > 0
        && (dyn_active(dyn_did) == 0 || dyn_active(dyn_did) == 1)
        && (dyn_online(dyn_did) == 0 || dyn_online(dyn_did) == 1)
        && dyn_privacy_ok;

    printf(
        "compat appkit dlsym ptrs load=%p main=%p display=%p width=%p height=%p active=%p online=%p screen_pre=%p image=%p imgw=%p imgh=%p bpp=%p row=%p provider=%p release=%p data=%p key=%p listen=%p ax=%p axopt=%p av=%p\n",
        (void *)dyn_load,
        (void *)dyn_main,
        (void *)dyn_display,
        (void *)dyn_width,
        (void *)dyn_height,
        (void *)dyn_active,
        (void *)dyn_online,
        (void *)dyn_screen_preflight,
        (void *)dyn_create_image,
        (void *)dyn_image_width,
        (void *)dyn_image_height,
        (void *)dyn_image_bpp,
        (void *)dyn_image_row,
        (void *)dyn_image_provider,
        (void *)dyn_image_release,
        (void *)dyn_provider_data,
        (void *)dyn_key_state,
        (void *)dyn_listen_preflight,
        (void *)dyn_ax,
        (void *)dyn_ax_options,
        avfoundation
    );
    printf(
        "compat appkit dlsym load=%d main=%d display=%u size=%zux%zu pass=%d\n",
        dyn_load_ret,
        dyn_main_ret,
        dyn_did,
        dyn_w,
        dyn_h,
        dyn_ok
    );
    printf(
        "compat privacy dlsym screen_access=%d image=%p image_size=%zux%zu bpp=%zu row=%zu provider=%p data=%p data_len=%ld key_a=%d listen_access=%d ax=%d axopt=%d avclass=%p mic_auth=%lu mic=%p mic_name=%s pass=%d\n",
        dyn_screen_access,
        dyn_image,
        dyn_image_w,
        dyn_image_h,
        dyn_image_bits,
        dyn_image_stride,
        dyn_provider,
        dyn_pixels,
        dyn_pixels_len,
        dyn_key_a,
        dyn_listen_access,
        dyn_ax_trusted,
        dyn_ax_trusted_options,
        dyn_capture_device_class,
        (unsigned long)dyn_mic_auth,
        dyn_default_audio,
        utf8_or_null(dyn_audio_name),
        dyn_privacy_ok
    );
    return static_ok && dyn_ok ? 0 : 1;
}
"#,
    )
    .expect("failed to write generated arm64 AppKit startup fixture");

    let output = Command::new("xcrun")
        .arg("clang")
        .arg("-target")
        .arg("arm64-apple-macos11")
        .arg("-mmacosx-version-min=11.0")
        .arg("-fno-builtin")
        .arg("-fno-builtin-printf")
        .arg("-fno-stack-protector")
        .arg(&source)
        .arg("-framework")
        .arg("AppKit")
        .arg("-framework")
        .arg("CoreGraphics")
        .arg("-framework")
        .arg("CoreFoundation")
        .arg("-framework")
        .arg("ApplicationServices")
        .arg("-framework")
        .arg("AVFoundation")
        .arg("-framework")
        .arg("Foundation")
        .arg("-lobjc")
        .arg("-o")
        .arg(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch xcrun clang for generated arm64 AppKit startup fixture");
    assert!(
        output.status.success(),
        "failed to compile generated arm64 AppKit startup fixture with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[cfg(not(target_os = "macos"))]
#[test]
fn compat_mode_smoke_is_macos_only() {
    eprintln!(
        "skipping macOS compat-mode integration test on {}",
        std::env::consts::OS
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_executes_arm64_hello_without_analysis_trace_plugins() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode integration test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = fixture_path();
    if !fixture.is_file() {
        eprintln!(
            "skipping compat-mode integration test: fixture not present at {}",
            fixture.display()
        );
        return;
    }

    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        // The compat trace bus intentionally has no analysis plugin preset,
        // so enable legacy startup diagnostics only for this smoke test. These
        // markers prove Unicorn entered guest arm64 code and returned through
        // the synthetic done address instead of merely accepting the CLI input.
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let startup_marker = stdout
        .lines()
        .find(|line| line.contains("[STARTUP][arm64 #00] pc="))
        .unwrap_or("<missing startup marker>");
    let done_marker = stdout
        .lines()
        .find(|line| {
            line.contains("[THREAD][arm64] reached done_addr")
                || line.contains("[STARTUP][arm64] reached done_addr")
        })
        .unwrap_or("<missing done marker>");

    eprintln!(
        "compat proof: host={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    eprintln!(
        "compat proof: command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof: status={status}");
    eprintln!("compat proof: guest stdout={guest_stdout:?}");
    eprintln!("compat proof: startup marker={startup_marker}");
    eprintln!("compat proof: done marker={done_marker}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof: stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstderr:\n{}",
        status,
        stderr
    );

    assert!(
        stdout.contains("Hello World"),
        "compat smoke did not proxy guest stdout from the arm64 fixture; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[STARTUP][arm64 #00] pc="),
        "compat smoke did not show the first guest instruction; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[THREAD][arm64] reached done_addr")
            || stdout.contains("[STARTUP][arm64] reached done_addr"),
        "compat smoke did not prove guest execution reached the synthetic done address; stdout:\n{stdout}"
    );
    for forbidden in [
        "\"plugin\":\"procmon\"",
        "\"plugin\":\"syscalls\"",
        "\"plugin\":\"filemon\"",
        "\"plugin\":\"memmon\"",
        "\"plugin\":\"detect\"",
        "\"plugin\":\"capture\"",
        "\"PayloadDumpFile\"",
        "\"SyntheticLogStream\"",
    ] {
        assert!(
            !stdout.contains(forbidden),
            "compat mode emitted analysis trace fragment {forbidden:?}\nstdout:\n{stdout}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_fresh_arm64_write_program() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode integration test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_write_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("printf,write")
        .arg("--compat-log-preview-bytes")
        .arg("96")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(write+dlsym): command={} --mode compat --compat-log calls --compat-log-filter printf,write --compat-log-preview-bytes 96 {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(write+dlsym): status={status}");
    eprintln!("compat proof(write+dlsym): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!(
            "compat proof(write+dlsym): stderr excerpt:\n{}",
            stderr_log_excerpt(&stderr, 6)
        );
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstderr:\n{}",
        status,
        stderr
    );
    assert!(
        stdout.contains("compat printf path"),
        "fresh arm64 fixture did not reach host-proxied _printf; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dlsym path"),
        "fresh arm64 fixture did not call a dlsym-returned guest trampoline; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat write path"),
        "fresh arm64 write fixture did not reach host-proxied _write; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[STARTUP][arm64 #00] pc="),
        "fresh arm64 write fixture did not show the first guest instruction; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[THREAD][arm64] reached done_addr")
            || stdout.contains("[STARTUP][arm64] reached done_addr"),
        "fresh arm64 write fixture did not prove guest execution reached done_addr; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"plugin\":\"compat\""),
        "compat CLI log option did not emit compat JSONL to stderr; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"Call\":\"printf\""),
        "compat log did not include normalized printf call; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"Symbol\":\"_printf\"") || stderr.contains("\"Symbol\":\"printf\""),
        "compat log did not preserve the proxied printf symbol; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"Call\":\"write\""),
        "compat log did not include host-proxied write call; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("\"Call\":\"dlopen\"") && !stderr.contains("\"Call\":\"dlsym\""),
        "compat log filter leaked unrequested dynamic loader calls; stderr:\n{stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_host_user_identity_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode identity test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_identity_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("verbose")
        .arg("--compat-log-filter")
        .arg("getuid,getpwuid,getpwnam,getlogin_r,getgroups")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(identity): command={} --mode compat --compat-log verbose --compat-log-filter getuid,getpwuid,getpwnam,getlogin_r,getgroups {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(identity): status={status}");
    eprintln!("compat proof(identity): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!(
            "compat proof(identity): stderr excerpt:\n{}",
            stderr_log_excerpt(&stderr, 12)
        );
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat identity") && stdout.contains(" ok=1"),
        "identity fixture did not observe host-backed passwd/login/group data; stdout:\n{stdout}"
    );
    for fragment in [
        "\"Call\":\"getuid\"",
        "\"Call\":\"getpwuid\"",
        "\"Call\":\"getpwnam\"",
        "\"Call\":\"getlogin_r\"",
        "\"Call\":\"getgroups\"",
        "\"Model\":\"host-userdb\"",
        "\"Dir\":\"",
        "\"Shell\":\"",
    ] {
        assert!(
            stderr.contains(fragment),
            "compat identity log did not contain fragment {fragment:?}; stderr:\n{stderr}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_preserves_arm64_printf_stack_varargs() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode printf varargs test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_printf_varargs_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("printf")
        .arg("--compat-log-preview-bytes")
        .arg("128")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(printf-varargs): command={} --mode compat --compat-log calls --compat-log-filter printf --compat-log-preview-bytes 128 {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(printf-varargs): status={status}");
    eprintln!("compat proof(printf-varargs): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!(
            "compat proof(printf-varargs): stderr excerpt:\n{}",
            stderr_log_excerpt(&stderr, 6)
        );
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains(
            "compat varargs static ints=1,2,3,4,5,6,7,8,9,10 str=stack-ok hex=0x5a ptr=0x1234 char=Z"
        ),
        "printf varargs fixture did not preserve static import stack arguments; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "compat varargs dlsym ints=1,2,3,4,5,6,7,8,9,10 str=stack-ok hex=0x5a ptr=0x1234 char=Z"
        ),
        "printf varargs fixture did not preserve dlsym import stack arguments; stdout:\n{stdout}"
    );
    assert!(
        stderr.matches("\"Call\":\"printf\"").count() >= 2,
        "compat printf varargs run did not emit static and dlsym printf logs; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"sp\":\"0x"),
        "compat printf varargs log did not include the arm64 stack pointer; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("\"Call\":\"dlopen\"") && !stderr.contains("\"Call\":\"dlsym\""),
        "compat printf varargs log filter leaked unrequested dynamic-loader calls; stderr:\n{stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_lifecycle_glue() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode lifecycle glue diagnostic on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_lifecycle_glue_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("write")
        .arg("--compat-log-preview-bytes")
        .arg("128")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[') && !line.starts_with('{')
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let saw_ctor = stdout.contains("compat lifecycle ctor");
    let saw_main = stdout.contains("compat lifecycle main atexit_ret=");
    let saw_atexit = stdout.contains("compat lifecycle atexit");
    let saw_dtor = stdout.contains("compat lifecycle dtor");
    let main_hits = stdout.matches("compat lifecycle main atexit_ret=").count();

    eprintln!(
        "compat proof(lifecycle-glue): command={} --mode compat --compat-log calls --compat-log-filter write --compat-log-preview-bytes 128 {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(lifecycle-glue): status={status}");
    eprintln!(
        "compat proof(lifecycle-glue): guest stdout={:?}",
        text_excerpt(&guest_stdout, 512)
    );
    eprintln!(
        "compat proof(lifecycle-glue): observed ctor={} main={} main_hits={} atexit={} dtor={}",
        saw_ctor as u8, saw_main as u8, main_hits, saw_atexit as u8, saw_dtor as u8
    );
    if !stderr.trim().is_empty() {
        eprintln!(
            "compat proof(lifecycle-glue): stderr excerpt:\n{}",
            stderr_log_excerpt(&stderr, 8)
        );
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        saw_ctor,
        "lifecycle glue fixture did not execute __mod_init_func constructor; stdout:\n{stdout}"
    );
    assert!(
        saw_main,
        "lifecycle glue fixture did not reach main/atexit registration; stdout:\n{stdout}"
    );
    assert_eq!(
        main_hits, 1,
        "lifecycle glue fixture re-entered main instead of returning to done_addr; stdout excerpt:\n{}",
        text_excerpt(&stdout, 2048)
    );
    assert!(
        saw_atexit,
        "lifecycle glue fixture did not run registered atexit handlers; stdout:\n{stdout}"
    );
    assert!(
        saw_dtor,
        "lifecycle glue fixture did not run __mod_term_func destructors; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Call\":\"write\""),
        "lifecycle glue fixture did not log host-proxied constructor write; stderr:\n{stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_models_exec_as_nonreturning_spawn() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode exec model diagnostic on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_exec_model_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("verbose")
        .arg("--compat-log-filter")
        .arg("execl,fflush,fputs,fileno")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    eprintln!(
        "compat proof(exec): command={} --mode compat --compat-log verbose --compat-log-filter execl,fflush,fputs,fileno {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(exec): status={status}");
    eprintln!("compat proof(exec): stdout={stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(exec): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "exec model fixture exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat exec stdio stdout")
            && stdout.contains("compat exec before stdin_fd=0 stdout_fd=1 stderr_fd=2")
            && stdout.contains("compat exec child"),
        "exec model fixture did not run pre-exec code and spawned /bin/echo child; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("compat exec stdio stderr"),
        "exec model fixture did not write through guest stderr before execl; stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("compat exec after"),
        "exec model returned to old guest image after successful execl; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Call\":\"execl\"")
            && stderr.contains("\"Model\":\"spawn-wait-stop\"")
            && stderr.contains("\"Path\":\"/bin/echo\"")
            && stderr.contains("\"ExitStatus\":\"0\""),
        "exec model did not log spawned non-returning execl; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"Call\":\"fflush\"")
            && stderr.contains("\"return\":\"0\"")
            && stderr.contains("\"FailedProxies\":0"),
        "exec model did not successfully flush guest stdout before execl; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"Call\":\"fileno\"")
            && stderr.contains("\"Call\":\"fputs\"")
            && stderr.contains("\"return\":\"0\"")
            && stderr.contains("\"return\":\"1\"")
            && stderr.contains("\"return\":\"2\""),
        "exec model did not log successful standard stream fileno/fputs proxies; stderr:\n{stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_guest_library_constructors() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS guest-library constructor diagnostic on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let (fixture, dylib) = compile_arm64_guest_library_init_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("printf,write")
        .arg("--compat-log-preview-bytes")
        .arg("128")
        .arg(&fixture)
        .env("COMPATRA_GUEST_LIBS", &dylib)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_TRACE_PROFILE", "full")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[') && !line.starts_with('{')
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let saw_ctor = stdout.contains("compat guestlib ctor");
    let saw_main = stdout.contains("compat guestlib main value=42 text=ready");
    let saw_dtor = stdout.contains("compat guestlib dtor");
    let saw_registry = stdout.contains("\"Event\":\"guest-image-registry\"");
    let saw_image =
        stdout.contains("\"Event\":\"guest-image\"") && stdout.contains("libguest_state.dylib");
    let saw_binding = stdout.contains("\"Event\":\"guest-library-bindings\"")
        && stdout.contains("_guest_state_value");
    let saw_init_trace = stdout.contains("\"Event\":\"guest-library-mod-init-handlers\"");

    eprintln!(
        "compat proof(guest-library-init): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!(
        "compat proof(guest-library-init): COMPATRA_GUEST_LIBS={}",
        dylib.display()
    );
    eprintln!("compat proof(guest-library-init): status={status}");
    eprintln!(
        "compat proof(guest-library-init): guest stdout={:?}",
        text_excerpt(&guest_stdout, 512)
    );
    eprintln!(
        "compat proof(guest-library-init): observed ctor={} main={} dtor={} registry={} image={} binding={} init_trace={}",
        saw_ctor as u8,
        saw_main as u8,
        saw_dtor as u8,
        saw_registry as u8,
        saw_image as u8,
        saw_binding as u8,
        saw_init_trace as u8,
    );
    if !stderr.trim().is_empty() {
        eprintln!(
            "compat proof(guest-library-init): stderr excerpt:\n{}",
            stderr_log_excerpt(&stderr, 12)
        );
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        saw_ctor,
        "guest library constructor did not execute before main; stdout:\n{stdout}"
    );
    assert!(
        saw_main,
        "guest library export did not observe constructor-initialized state; stdout:\n{stdout}"
    );
    assert!(
        saw_dtor,
        "guest library destructor did not run through compat exit handlers; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Call\":\"write\"") && stderr.contains("\"Call\":\"printf\""),
        "guest library fixture did not log host-proxied write and printf calls; stderr:\n{stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_native_slice_for_universal_binary() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS universal native compat test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_universal_native_preferred_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("verbose")
        .arg("--compat-log-filter")
        .arg("gethostname,uname,sysctl,sysctlbyname")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    eprintln!(
        "compat proof(fat-native): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(fat-native): status={status}");
    eprintln!("compat proof(fat-native): stdout={stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(fat-native): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat fat native slice=x86_64"),
        "universal fixture did not run the native x86_64 slice; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("compat fat native slice=arm64"),
        "universal fixture unexpectedly ran the arm64 slice; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("[STARTUP][arm64 #00]"),
        "universal fixture was emulated instead of using the native fast path; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_memory_and_string_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode memory/string test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_memory_string_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(memory/string): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(memory/string): status={status}");
    eprintln!("compat proof(memory/string): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(memory/string): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat memstr static dst=alpha")
            && stdout.contains("overlap=ababcd")
            && stdout.contains("heap=heap-ok")
            && stdout.contains("zero_ok=1")
            && stdout.contains("bzero_ok=1")
            && stdout.contains("aligned_mod=0")
            && stdout.contains("hit=4 last=9 ok=1"),
        "memory/string fixture did not complete static import roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr-extra static memchr=5 memmem=6 memempty=0 case=6")
            && stdout.contains("lcpy=9 small=wallet-")
            && stdout.contains("lcat=8 cat=keychain")
            && stdout.contains("trunc=6 short=abcde")
            && stdout.contains("strtol=-42 end=6")
            && stdout.contains("strtoul=493 uend=4")
            && stdout.contains("strtoull=18446744073709551615 ullend=20 atoi=1234 ok=1"),
        "memory/string fixture did not complete extra static libc roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr dlsym ptrs malloc=0x")
            && stdout.contains(" memcpy=0x")
            && stdout.contains(" bzero=0x")
            && stdout.contains(" strcmp=0x")
            && stdout.contains(" strdup=0x")
            && stdout.contains(" posix_memalign=0x"),
        "memory/string fixture did not receive dlsym memory/string trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr-extra dlsym ptrs memchr=0x")
            && stdout.contains(" memmem=0x")
            && stdout.contains(" strcasecmp=0x")
            && stdout.contains(" strlcpy=0x")
            && stdout.contains(" strcasestr=0x")
            && stdout.contains(" strtoull=0x"),
        "memory/string fixture did not receive dlsym extra libc trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr dlsym dst=alpha")
            && stdout.contains("overlap=ababcd")
            && stdout.contains("heap=heap-ok")
            && stdout.contains("zero_ok=1")
            && stdout.contains("bzero_ok=1")
            && stdout.contains("aligned_mod=0")
            && stdout.contains("hit=4 last=9 ok=1"),
        "memory/string fixture did not complete dynamic import roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr-extra dlsym memchr=5 memmem=6 memempty=0 case=6")
            && stdout.contains("lcpy=9 small=wallet-")
            && stdout.contains("lcat=8 cat=keychain")
            && stdout.contains("trunc=6 short=abcde")
            && stdout.contains("strtol=-42 end=6")
            && stdout.contains("strtoul=493 uend=4")
            && stdout.contains("strtoull=18446744073709551615 ullend=20 atoi=1234 ok=1"),
        "memory/string fixture did not complete extra dlsym libc roundtrip; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_startup_glue_and_libcpp_scalar_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode startup glue test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_startup_glue_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("verbose")
        .arg("--compat-log-filter")
        .arg("mlock,munlock,madvise,pthread_sigmask,pthread_threadid_np,issetugid,issetguid,execl,system,next_prime,cxa_guard_acquire,cxa_guard_release,cxa_guard_abort")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(startup glue): command={} --mode compat --compat-log verbose --compat-log-filter mlock,munlock,madvise,pthread_sigmask,pthread_threadid_np,issetugid,issetguid,execl,system,next_prime,cxa_guard_acquire,cxa_guard_release,cxa_guard_abort {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(startup glue): status={status}");
    eprintln!("compat proof(startup glue): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(startup glue): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat startup glue static mlock=0 munlock=0 madvise=0 mask=0")
            && stdout.contains("oldmask_sum=0")
            && stdout.contains("threadid=0 thread_id=1")
            && stdout.contains("issetugid=0 execl=-1")
            && stdout.contains("system=0")
            && stdout.contains("next_prime=1009")
            && stdout.contains("guard_first=1 guard_second=0 guard=0x1")
            && stdout.contains("guard_abort_first=1 guard_abort_second=1")
            && stdout.contains("str_len=9 str_accessor_proxy=0 str_size=0 str_length=0 str_empty=-1 str_text=glue-cxx! str_find=4 str_compare=0 cstr_ok=0 data_ok=0 str_lifecycle_proxy=0 str_lifecycle_ok=0 str_mutator_proxy=0 str_capacity=0 reserve_capacity=0 reserve_ge_40=0 resize_ok=0 shrink_ok=0 clear_ok=0 str_ok=1")
            && stdout.contains("vec_proxy=0 vec_size=0 vec_capacity=0 vec_data_ok=0 vec_access_proxy=0 vec_access_ok=0 vec_pushed_size=0 vec_popped_size=0 vec_lifecycle_proxy=0 vec_lifecycle_ok=0 vec_clear_ok=0 vec_ok=1")
            && stdout.contains("ok=1"),
        "startup glue fixture did not complete static import roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat startup glue dlsym ptrs mlock=0x")
            && stdout.contains(" munlock=0x")
            && stdout.contains(" madvise=0x")
            && stdout.contains(" pthread_sigmask=0x")
            && stdout.contains(" pthread_threadid_np=0x")
            && stdout.contains(" issetugid=0x")
            && stdout.contains(" execl=0x")
            && stdout.contains(" system=0x")
            && stdout.contains(" next_prime=0x")
            && stdout.contains(" cxa_guard_acquire=0x")
            && stdout.contains(" cxa_guard_release=0x")
            && stdout.contains(" cxa_guard_abort=0x")
            && stdout.contains(" string_init=0x")
            && stdout.contains(" string_append=0x")
            && stdout.contains(" string_push=0x")
            && stdout.contains(" string_find=0x")
            && stdout.contains(" string_compare=0x")
            && stdout.contains(" string_size=0x")
            && stdout.contains(" string_length=0x")
            && stdout.contains(" string_empty=0x")
            && stdout.contains(" string_cstr=0x")
            && stdout.contains(" string_data=0x")
            && stdout.contains(" string_capacity=0x")
            && stdout.contains(" string_clear=0x")
            && stdout.contains(" string_reserve=0x")
            && stdout.contains(" string_resize=0x")
            && stdout.contains(" string_resize_fill=0x")
            && stdout.contains(" string_ctor=0x")
            && stdout.contains(" string_assign=0x")
            && stdout.contains(" string_dtor=0x")
            && stdout.contains(" vector_size=0x")
            && stdout.contains(" vector_capacity=0x")
            && stdout.contains(" vector_empty=0x")
            && stdout.contains(" vector_data=0x")
            && stdout.contains(" vector_clear=0x")
            && stdout.contains(" vector_reserve=0x")
            && stdout.contains(" vector_resize_fill=0x")
            && stdout.contains(" vector_begin=0x")
            && stdout.contains(" vector_end=0x")
            && stdout.contains(" vector_index=0x")
            && stdout.contains(" vector_front=0x")
            && stdout.contains(" vector_back=0x")
            && stdout.contains(" vector_push=0x")
            && stdout.contains(" vector_pop=0x")
            && stdout.contains(" vector_ctor=0x")
            && stdout.contains(" vector_copy=0x")
            && stdout.contains(" vector_assign=0x")
            && stdout.contains(" vector_dtor=0x"),
        "startup glue fixture did not receive dlsym trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat startup glue dlsym mlock=0 munlock=0 madvise=0 mask=0")
            && stdout.contains("oldmask_sum=0")
            && stdout.contains("threadid=0 thread_id=1")
            && stdout.contains("issetugid=0 execl=-1")
            && stdout.contains("system=0")
            && stdout.contains("next_prime=1009")
            && stdout.contains("guard_first=1 guard_second=0 guard=0x1")
            && stdout.contains("guard_abort_first=1 guard_abort_second=1")
            && stdout.contains("str_len=9 str_accessor_proxy=1 str_size=9 str_length=9 str_empty=0 str_text=glue-cxx! str_find=4 str_compare=0 cstr_ok=1 data_ok=1 str_lifecycle_proxy=1 str_lifecycle_ok=1 str_mutator_proxy=1 str_capacity=22")
            && stdout.contains("reserve_ge_40=1 resize_ok=1 shrink_ok=1 clear_ok=1 str_ok=1")
            && stdout.contains("vec_proxy=1 vec_size=6")
            && stdout.contains("vec_data_ok=1 vec_access_proxy=1 vec_access_ok=1 vec_pushed_size=7 vec_popped_size=6 vec_lifecycle_proxy=1 vec_lifecycle_ok=1 vec_clear_ok=1 vec_ok=1")
            && stdout.contains("ok=1"),
        "startup glue fixture did not complete dynamic import roundtrip; stdout:\n{stdout}"
    );
    for fragment in [
        "\"Call\":\"mlock\"",
        "\"Call\":\"munlock\"",
        "\"Call\":\"madvise\"",
        "\"Call\":\"pthread_sigmask\"",
        "\"Call\":\"pthread_threadid_np\"",
        "issetugid",
        "\"Call\":\"execl\"",
        "\"Call\":\"system\"",
        "\"Command\":\"exit 0\"",
        "\"Call\":\"next_prime\"",
        "\"Symbol\":\"__next_prime\"",
        "__cxa_guard_acquire",
        "__cxa_guard_release",
        "__cxa_guard_abort",
    ] {
        assert!(
            stderr.contains(fragment),
            "startup glue compat log missing fragment {fragment:?}\nstderr:\n{stderr}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_corefoundation_and_security_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode Apple framework test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_apple_framework_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(apple frameworks): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(apple frameworks): status={status}");
    eprintln!("compat proof(apple frameworks): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(apple frameworks): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.lines().any(|line| line.contains(
            "compat apple static cf ok=1 len=9 text=static-cf data_len=6 data_text=cfdata type_ok=1"
        ) && line.contains(" pass=1")),
        "Apple framework fixture did not complete static CoreFoundation/Security calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat apple dlsym ptrs create=0x")
            && stdout.contains(" get=0x")
            && stdout.contains(" len=0x")
            && stdout.contains(" data_create=0x")
            && stdout.contains(" data_len=0x")
            && stdout.contains(" data_bytes=0x")
            && stdout.contains(" get_type=0x")
            && stdout.contains(" string_type=0x")
            && stdout.contains(" data_type=0x")
            && stdout.contains(" url_create_string=0x")
            && stdout.contains(" url_get_string=0x")
            && stdout.contains(" array_mut=0x")
            && stdout.contains(" array_append=0x")
            && stdout.contains(" array_insert=0x")
            && stdout.contains(" array_set=0x")
            && stdout.contains(" array_remove=0x")
            && stdout.contains(" array_remove_all=0x")
            && stdout.contains(" array_contains=0x")
            && stdout.contains(" array_count=0x")
            && stdout.contains(" array_get=0x")
            && stdout.contains(" set_create=0x")
            && stdout.contains(" set_mut=0x")
            && stdout.contains(" set_add=0x")
            && stdout.contains(" set_set=0x")
            && stdout.contains(" set_replace=0x")
            && stdout.contains(" set_remove=0x")
            && stdout.contains(" set_remove_all=0x")
            && stdout.contains(" set_contains=0x")
            && stdout.contains(" set_count=0x")
            && stdout.contains(" set_get=0x")
            && stdout.contains(" set_get_present=0x")
            && stdout.contains(" dict_mut=0x")
            && stdout.contains(" dict_set=0x")
            && stdout.contains(" dict_add=0x")
            && stdout.contains(" dict_replace=0x")
            && stdout.contains(" dict_remove=0x")
            && stdout.contains(" dict_remove_all=0x")
            && stdout.contains(" dict_get=0x")
            && stdout.contains(" dict_count=0x")
            && stdout.contains(" random=0x")
            && stdout.contains(" error=0x")
            && stdout.contains(" item_copy=0x")
            && stdout.contains(" item_add=0x")
            && stdout.contains(" item_delete=0x")
            && stdout.contains(" kc_default=0x")
            && stdout.contains(" kc_open=0x")
            && stdout.contains(" kc_path=0x")
            && stdout.contains(" kc_find=0x")
            && stdout.contains(" kc_search_create=0x")
            && stdout.contains(" kc_search_next=0x")
            && stdout.contains(" kc_content=0x")
            && stdout.contains(" kc_free=0x"),
        "Apple framework fixture did not receive dlsym Apple trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.contains(
            "compat apple dlsym cf ok=1 len=6 text=dyn-cf data_len=7 data_text=dyndata type_ok=1"
        ) && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym CoreFoundation/Security calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfarray static")
                && line.contains(" count=3 ")
                && line.contains(" contains_gamma=1")
                && line.contains(" after_remove=2 ")
                && line.contains(" empty=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete static CFArray mutation calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfarray dlsym")
                && line.contains(" count=3 ")
                && line.contains(" contains_gamma=1")
                && line.contains(" after_remove=2 ")
                && line.contains(" empty=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym CFArray mutation calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfset static")
                && line.contains(" immutable_count=2 ")
                && line.contains(" immutable_contains=1")
                && line.contains(" duplicate_count=2 ")
                && line.contains(" present=1")
                && line.contains(" replaced=1")
                && line.contains(" after_set=3 ")
                && line.contains(" empty=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete static CFSet mutation calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfset dlsym")
                && line.contains(" immutable_count=2 ")
                && line.contains(" immutable_contains=1")
                && line.contains(" duplicate_count=2 ")
                && line.contains(" present=1")
                && line.contains(" replaced=1")
                && line.contains(" after_set=3 ")
                && line.contains(" empty=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym CFSet mutation calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfurl static")
                && line.contains(" text_ok=1")
                && line.contains(" text=https://example.com/compatra?mode=compat")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete static CFURL string calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat cfurl dlsym")
                && line.contains(" text_ok=1")
                && line.contains(" text=https://example.com/compatra?mode=compat")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym CFURL string calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security static") && line.contains(" pass=1")),
        "Apple framework fixture did not complete static Security/keychain calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-search static")
                && line.contains(" skipped=1")
                && line.contains(" reason=ci-noninteractive-keychain")
                && line.contains(" pass=1")),
        "Apple framework fixture did not mark static Security keychain probes as skipped in CI; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-secitem static")
                && line.contains(" const=1")
                && line.contains(" class=class")
                && line.contains(" value=v_Data")
                && line.contains(" bridge=1")
                && line.contains(" pass=1")),
        "Apple framework fixture did not bridge static guest CFDictionary SecItem queries into host Security; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-secitem-mutable static")
                && line.contains(" ops=1")
                && line.contains(" bridge=1")
                && line.contains(" pass=1")),
        "Apple framework fixture did not bridge static mutable CFDictionary SecItem queries into host Security; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat iokit static")
                && line.contains(" name_ret=0 ")
                && line.contains(" path_ret=0 ")
                && line.contains(" id_ret=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete static IOKit registry calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat iokit dlsym ptrs matching=0x")
            && stdout.contains(" get_service=0x")
            && stdout.contains(" get_name=0x")
            && stdout.contains(" get_path=0x")
            && stdout.contains(" get_id=0x")
            && stdout.contains(" property=0x")
            && stdout.contains(" release=0x"),
        "Apple framework fixture did not receive dlsym IOKit trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security dlsym") && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym Security/keychain calls; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-search dlsym")
                && line.contains(" skipped=1")
                && line.contains(" reason=ci-noninteractive-keychain")
                && line.contains(" pass=1")),
        "Apple framework fixture did not mark dlsym Security keychain probes as skipped in CI; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-secitem dlsym")
                && line.contains(" const=1")
                && line.contains(" class=class")
                && line.contains(" value=v_Data")
                && line.contains(" bridge=1")
                && line.contains(" pass=1")),
        "Apple framework fixture did not bridge dlsym guest CFDictionary SecItem queries into host Security; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat security-secitem-mutable dlsym")
                && line.contains(" ops=1")
                && line.contains(" bridge=1")
                && line.contains(" pass=1")),
        "Apple framework fixture did not bridge dlsym mutable CFDictionary SecItem queries into host Security; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat iokit dlsym")
                && line.contains(" name_ret=0 ")
                && line.contains(" path_ret=0 ")
                && line.contains(" id_ret=0 ")
                && line.contains(" pass=1")),
        "Apple framework fixture did not complete dlsym IOKit registry calls; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_foundation_startup_glue() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode Foundation startup test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_foundation_startup_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(foundation startup): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(foundation startup): status={status}");
    eprintln!("compat proof(foundation startup): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(foundation startup): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.lines().any(|line| line.contains("compat foundation static ")
            && line.contains(" paths=")
            && line.contains(" process=")
            && line.contains(" args=")
            && line.contains(" env_home=")
            && line.contains(" bundle=")
            && line.contains(" exists=1 isdir=1 ")
            && line.contains(" data_len=18 write=1 roundtrip=18 ")
            && line.contains(" enum_first=")
            && line.contains(" enum_second=")
            && line.contains(" enum_done_null=1 ")
            && line.contains(" pass=1")),
        "Foundation startup fixture did not complete static NSProcessInfo/NSBundle/NSFileManager/Foundation file-data glue; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat foundation dlsym ptrs home=0x")
            && stdout.contains(" temp=0x")
            && stdout.contains(" paths=0x")
            && stdout.contains(" selector=0x")
            && stdout.contains(" selname=0x"),
        "Foundation startup fixture did not receive dlsym Foundation trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat foundation dlsym ")
                && line.contains(" paths=")
                && line.contains(" sel=processName")
                && line.contains(" pass=1")),
        "Foundation startup fixture did not complete dlsym Foundation calls; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_appkit_startup_glue() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode AppKit startup test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_appkit_startup_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let proof_lines = stdout
        .lines()
        .filter(|line| line.contains("compat appkit") || line.contains("compat privacy"))
        .collect::<Vec<_>>()
        .join("\n");

    eprintln!(
        "compat proof(appkit startup): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(appkit startup): status={status}");
    eprintln!("compat proof(appkit startup): lines:\n{proof_lines}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(appkit startup): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat appkit static ")
                && line.contains(" load=1 ")
                && line.contains(" app=0x")
                && line.contains(" set=1 ")
                && line.contains(" running=0 ")
                && line.contains(" main=1/1 ")
                && line.contains(" runloop=0x")
                && line.contains(" screen=0x")
                && line.contains(" screens=1")
                && line.contains(" name=Compatibility Display")
                && line.contains(" window=0x")
                && line.contains(" title=Compatibility Window")
                && line.contains(" display=")
                && line.contains(" active=")
                && line.contains(" online=")
                && line.contains(" appmain=0 ")
                && line.contains(" pass=1")),
        "AppKit startup fixture did not complete static UI glue; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat appkit dlsym ptrs load=0x")
            && stdout.contains(" main=0x")
            && stdout.contains(" display=0x")
            && stdout.contains(" width=0x")
            && stdout.contains(" height=0x")
            && stdout.contains(" active=0x")
            && stdout.contains(" online=0x")
            && stdout.contains(" screen_pre=0x")
            && stdout.contains(" image=0x")
            && stdout.contains(" imgw=0x")
            && stdout.contains(" imgh=0x")
            && stdout.contains(" bpp=0x")
            && stdout.contains(" row=0x")
            && stdout.contains(" provider=0x")
            && stdout.contains(" release=0x")
            && stdout.contains(" data=0x")
            && stdout.contains(" key=0x")
            && stdout.contains(" listen=0x")
            && stdout.contains(" ax=0x")
            && stdout.contains(" axopt=0x")
            && stdout.contains(" av=0x"),
        "AppKit startup fixture did not receive dlsym UI trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat appkit dlsym ")
                && line.contains(" load=1 ")
                && line.contains(" main=0 ")
                && line.contains(" display=")
                && line.contains(" size=")
                && line.contains(" pass=1")),
        "AppKit startup fixture did not complete dlsym UI glue; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat privacy static ") && line.contains(" pass=1")),
        "AppKit startup fixture did not complete static privacy-sensitive probes; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat privacy dlsym ") && line.contains(" pass=1")),
        "AppKit startup fixture did not complete dlsym privacy-sensitive probes; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_network_resolver_and_socket_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode network test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_network_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(network): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(network): status={status}");
    eprintln!("compat proof(network): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(network): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat gai static ret=0"),
        "network fixture did not complete static getaddrinfo; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat gai dlsym ret=0"),
        "network fixture did not complete dlsym getaddrinfo; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dlsym network ptrs gai=0x")
            && stdout.contains("ifaddrs=0x")
            && stdout.contains("freeifaddrs=0x")
            && stdout.contains("ifindex=0x")
            && stdout.contains("reach=0x")
            && stdout.contains("flags=0x")
            && stdout.contains("proxies=0x")
            && stdout.contains("dict_count=0x")
            && stdout.contains("dict_value=0x")
            && stdout.contains("inet_addr=0x")
            && stdout.contains("ntohs=0x"),
        "network fixture did not receive dlsym trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat inet static addr=0x0100007f aton=1 text=10.20.30.40")
            && stdout.contains("ntohl=0x11223344")
            && stdout.contains("ntohs=0x1357"),
        "network fixture did not complete static inet/byte-order proxies; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat inet dlsym addr=0x0100007f aton=1 text=10.20.30.40")
            && stdout.contains("ntohl=0x11223344")
            && stdout.contains("ntohs=0x1357"),
        "network fixture did not complete dlsym inet/byte-order proxies; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat getnameinfo static ret=0 host=127.0.0.1 service=443"),
        "network fixture did not complete static getnameinfo proxy; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat getnameinfo dlsym ret=0 host=127.0.0.1 service=443"),
        "network fixture did not complete dlsym getnameinfo proxy; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.contains("compat ifaddrs static ret=0")
            && line.contains(" count=")
            && line.contains(" saw_lo=1 ")
            && line.contains(" lo_index=")),
        "network fixture did not complete static getifaddrs/if_nametoindex proxy; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("compat ifaddrs dlsym ret=0")
                && line.contains(" count=")
                && line.contains(" saw_lo=1 ")
                && line.contains(" lo_index=")),
        "network fixture did not complete dlsym getifaddrs/if_nametoindex proxy; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.contains("compat sc static ")
            && line.contains(" flags_ok=1 ")
            && line.contains(" proxies=0x")
            && line.contains(" count=")
            && line.contains(" number_ok=1 ")
            && line.contains(" http_value=")),
        "network fixture did not complete static SystemConfiguration reachability/proxy calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.contains("compat sc dlsym ")
            && line.contains(" flags_ok=1 ")
            && line.contains(" proxies=0x")
            && line.contains(" count=")
            && line.contains(" number_ok=1 ")
            && line.contains(" http_value=")),
        "network fixture did not complete dlsym SystemConfiguration reachability/proxy calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat sendmsg static sent=6 recv=6 text=msg-ok"),
        "network fixture did not complete static sendmsg/recvmsg roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat sendmsg dlsym sent=6 recv=6 text=msg-ok"),
        "network fixture did not complete dlsym sendmsg/recvmsg roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat socketpair ret=0"),
        "network fixture did not create a host socketpair; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat socketpair io sent=6 recv=6 text=net-ok"),
        "network fixture did not send and receive through host-proxied dynamic socket imports; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_public_network_probe_reports_result_or_reason() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode public network probe on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_public_network_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("getaddrinfo,connect,send,recv,poll,getsockopt")
        .arg("--compat-log-preview-bytes")
        .arg("96")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let proof_lines = stdout
        .lines()
        .filter(|line| line.contains("compat publicnet"))
        .collect::<Vec<_>>()
        .join("\n");

    eprintln!(
        "compat proof(publicnet): command={} --mode compat --compat-log calls --compat-log-filter getaddrinfo,connect,send,recv,poll,getsockopt --compat-log-preview-bytes 96 {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(publicnet): status={status}");
    eprintln!("compat proof(publicnet): lines:\n{proof_lines}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(publicnet): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "public network probe fixture exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat publicnet static resolve host=example.com service=80 ret=")
            && stdout.contains("compat publicnet static summary attempted=1"),
        "public network probe did not report static outbound attempt; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat publicnet dlsym ptrs gai=0x")
            && stdout.contains(" connect=0x")
            && stdout.contains(" poll=0x"),
        "public network probe did not receive dlsym network trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat publicnet dlsym summary attempted=1")
            || stdout.contains("compat publicnet dlsym summary attempted=0"),
        "public network probe did not report dynamic outbound attempt or reason; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Call\":\"getaddrinfo\""),
        "public network probe did not emit getaddrinfo compat log; stderr:\n{stderr}"
    );
    if stderr.contains("\"Call\":\"connect\"") {
        assert!(
            stderr.contains("\"Endpoint\":\""),
            "public network probe connect log did not include decoded endpoint; stderr:\n{stderr}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "deep Intel macOS network compatibility matrix; CI opts in with --include-ignored"]
fn compat_mode_network_stack_matrix_manual() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode network matrix on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_network_matrix_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("calls")
        .arg("--compat-log-filter")
        .arg("connect")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "long")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let proof_lines = stdout
        .lines()
        .filter(|line| line.contains("compat netmatrix"))
        .collect::<Vec<_>>()
        .join("\n");

    eprintln!(
        "compat proof(netmatrix): command={} --mode compat --compat-log calls --compat-log-filter connect {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(netmatrix): status={status}");
    eprintln!("compat proof(netmatrix): lines:\n{proof_lines}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(netmatrix): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "network matrix fixture exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat netmatrix resolver static ok_ret=0")
            && stdout.contains("compat netmatrix resolver dlsym ok_ret=0"),
        "network matrix did not complete resolver checks; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat netmatrix udp static")
            && stdout.contains("sendto=7 recvfrom=7 text=udp-one")
            && stdout.contains("compat netmatrix udp dlsym"),
        "network matrix did not complete UDP sendto/recvfrom checks; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat netmatrix udp-msg static sendmsg=7 recvmsg=7 text=msg-udp")
            && stdout.contains("compat netmatrix udp-msg dlsym sendmsg=7 recvmsg=7 text=msg-udp"),
        "network matrix did not complete UDP sendmsg/recvmsg address checks; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat netmatrix tcp dlsym")
            && stdout.contains("sendrecv=6/6/tcp-ok")
            && stdout.contains("reply=5/5/reply")
            && stdout.contains("shutdown=0"),
        "network matrix did not complete TCP connect/accept/getpeername checks; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Call\":\"connect\"")
            && stderr.contains("\"Family\":\"AF_INET\"")
            && stderr.contains("\"Address\":\"127.0.0.1\"")
            && stderr.contains("\"Endpoint\":\"127.0.0.1:"),
        "network matrix compat log did not include decoded connect endpoint; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("compat netmatrix summary failures=0"),
        "network matrix reported failures; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_fd_vector_and_positioned_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode fd test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let (fixture, data_file) = compile_arm64_fd_fixture();
    let _ = fs::remove_file(&data_file);
    let compatra = compatra_binary();
    let scratch_root = generated_fixture_dir_arg();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .env("COMPATRA_ARGV_APPEND", &scratch_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(fd): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(fd): status={status}");
    eprintln!("compat proof(fd): scratch root={scratch_root}");
    eprintln!("compat proof(fd): data file={}", data_file.display());
    eprintln!("compat proof(fd): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(fd): stderr:\n{stderr}");
    }

    let _ = fs::remove_file(&data_file);

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat fd static writev=6 readv=6 text=vec-ok"),
        "fd fixture did not complete static pipe/writev/readv roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd select pipe=0 empty=0 ready=1 isset=1 byte=S"),
        "fd fixture did not complete select readiness probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd dup fd=") && stdout.contains("byte=D dup2_ret="),
        "fd fixture did not complete dup/dup2 probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd positioned fd=")
            && stdout.contains("pwrite=6 lseek=2 pread=6 text=pos-ok"),
        "fd fixture did not complete positioned file I/O probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd metadata fsync=0 ioctl=0 avail=2 statfs=0")
            && stdout.contains(" fstatfs=0 "),
        "fd fixture did not complete imported fsync/ioctl/statfs/fstatfs probes; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd nocancel io open=")
            && stdout.contains("write=5 seek=0 read=5")
            && stdout.contains("compat fd nocancel result text=nc-ok")
            && stdout.contains("close=0"),
        "fd fixture did not complete raw *_nocancel syscall I/O probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd raw syscalls pipe=0")
            && stdout.contains(" ioctl=0 avail=2 text=RP fsync=0 statfs=0")
            && stdout.contains(" fstatfs=0 "),
        "fd fixture did not complete raw pipe/ioctl/fsync/statfs syscalls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd at syscalls dir=")
            && stdout.contains(" read=1 ")
            && stdout.contains(" faccessat=0 fstatat=0 size="),
        "fd fixture did not complete raw dirfd-based openat/faccessat/fstatat syscalls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd dlsym ptrs open=0x")
            && stdout.contains(" read=0x")
            && stdout.contains(" write=0x")
            && stdout.contains(" close=0x")
            && stdout.contains(" pipe=0x"),
        "fd fixture did not receive dlsym trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd dlsym writev=6 readv=6 text=vec-ok"),
        "fd fixture did not complete dynamic pipe/writev/readv roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd dlsym rw io open=")
            && stdout.contains("write=5 seek=0 read=5")
            && stdout.contains("compat fd dlsym rw result text=rw-ok close=0"),
        "fd fixture did not complete dynamic open/write/read/close roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat fd dlsym positioned pwrite=6 lseek=16 pread=6 text=dyn-ok"),
        "fd fixture did not complete dynamic positioned file I/O probe; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_stdio_file_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode stdio test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let (fixture, data_file) = compile_arm64_stdio_fixture();
    let _ = fs::remove_file(&data_file);
    let compatra = compatra_binary();
    let scratch_root = generated_fixture_dir_arg();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .env("COMPATRA_ARGV_APPEND", &scratch_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(stdio): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(stdio): status={status}");
    eprintln!("compat proof(stdio): scratch root={scratch_root}");
    eprintln!("compat proof(stdio): data file={}", data_file.display());
    eprintln!("compat proof(stdio): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(stdio): stderr:\n{stderr}");
    }

    let _ = fs::remove_file(&data_file);

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat stdio static open=0x")
            && stdout.contains("fwrite=20")
            && stdout.contains("line=stdio-one read=10 text=stdio-two")
            && stdout.contains("tail=tail eof_read=0 eof=1 err=0 eof_after=0 close=0"),
        "stdio fixture did not complete static FILE* roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat stdio static fdopen fd=")
            && stdout.contains("read=5 text=stdio close=0"),
        "stdio fixture did not complete static fdopen/fread/fclose; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat stdio dlsym ptrs fopen=0x")
            && stdout.contains(" fread=0x")
            && stdout.contains(" clearerr=0x")
            && stdout.contains(" fileno=0x"),
        "stdio fixture did not receive dlsym stdio trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat stdio dlsym open=0x")
            && stdout.contains("line=stdio-one read=10 text=stdio-two")
            && stdout.contains("tail=tail eof_read=0 eof=1 err=0 eof_after=0 close=0"),
        "stdio fixture did not complete dynamic FILE* roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat stdio dlsym fdopen fd=")
            && stdout.contains("read=5 text=stdio close=0"),
        "stdio fixture did not complete dynamic fdopen/fread/fclose; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_path_metadata_and_mutation_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode path test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let (fixture, base_dir) = compile_arm64_path_fixture();
    let _ = fs::remove_dir_all(&base_dir);
    let compatra = compatra_binary();
    let scratch_root = generated_fixture_dir_arg();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .env("COMPATRA_ARGV_APPEND", &scratch_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(path): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(path): status={status}");
    eprintln!("compat proof(path): scratch root={scratch_root}");
    eprintln!("compat proof(path): base dir={}", base_dir.display());
    eprintln!("compat proof(path): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(path): stderr:\n{stderr}");
    }

    let _ = fs::remove_dir_all(&base_dir);

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat path cwd mkdir=0 chdir=0 ret=0x")
            && stdout.contains("path-host-root"),
        "path fixture did not complete static mkdir/chdir/getcwd; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path static stat access=0 stat=0 fstat=0 lstat=0")
            && stdout.contains("compat path static sizes stat=5 fstat=5"),
        "path fixture did not complete static access/stat/fstat; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path static mode chmod=0 fchmod=0 truncate=0 ftruncate=0"),
        "path fixture did not complete static chmod/truncate imports; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .contains("compat path static link symlink=0 readlink=9 target=alpha.txt realpath=0x"),
        "path fixture did not complete static symlink/readlink/lstat; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path static xattr set=0 get=8 text=xattr-ok")
            && stdout.contains(" has=1 remove=0"),
        "path fixture did not complete static xattr host proxy roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout
            .contains("compat path static mutate rename=0 unlink=0 unlink_link=0 mkdir=0 rmdir=0"),
        "path fixture did not complete static rename/unlink/rmdir; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "compat path raw syscall mode chmod=0 fchmod=0 fchmodat=0 truncate=0 ftruncate=0 size=4"
        ) && stdout.contains(
            "compat path raw at mkdirat=0 renameat=0 symlink=0 readlinkat=11 target=raw-new.txt unlinkat=0 unlink_link=0 rmdir=0"
        ),
        "path fixture did not complete raw syscall chmod/truncate/*at proof; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym ptrs 0x"),
        "path fixture did not receive dlsym path trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym at ptrs chmod=0x") && stdout.contains("readlinkat=0x"),
        "path fixture did not receive dlsym chmod/truncate/*at trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym xattr ptrs get=0x")
            && stdout.contains(" fget=0x")
            && stdout.contains(" fremove=0x"),
        "path fixture did not receive dlsym xattr trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym cwd mkdir=0 chdir=0 ret=0x")
            && stdout.contains("dyn-dir"),
        "path fixture did not complete dlsym chdir/getcwd; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym stat rename=0 access=0 stat=0 fstat=0 lstat=0")
            && stdout.contains("compat path dlsym sizes stat=7 fstat=7"),
        "path fixture did not complete dlsym path metadata; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "compat path dlsym link symlink=0 readlink=11 target=dyn-new.txt realpath=0x"
        ),
        "path fixture did not complete dlsym readlink/realpath; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym xattr set=0 get=12 text=dyn-xattr-ok")
            && stdout.contains("remove=0 fset=0 fget=11 ftext=fd-xattr-ok")
            && stdout.contains("fhas=1 fremove=0"),
        "path fixture did not complete dlsym xattr host proxy roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat path dlsym cleanup unlink=0 unlink_link=0 rmdir=0"),
        "path fixture did not complete dlsym cleanup mutators; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "compat path dlsym mode chmod=0 fchmod=0 truncate=0 ftruncate=0 size=4 unlink=0"
        ),
        "path fixture did not complete dlsym chmod/truncate imports; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "compat path dlsym at fchmodat=0 mkdirat=0 renameat=0 symlink=0 readlinkat=14 target=dyn-at-new.txt unlinkat=0 unlink_link=0 rmdir=0"
        ),
        "path fixture did not complete dlsym *at imports; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_env_time_resource_and_syscall_imports() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode env/time test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_env_time_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg("--compat-log")
        .arg("verbose")
        .arg("--compat-log-filter")
        .arg("gethostname,uname,sysctl,sysctlbyname,proc_pidpath,proc_name")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(env/time/syscall): command={} --mode compat --compat-log verbose --compat-log-filter gethostname,uname,sysctl,sysctlbyname,proc_pidpath,proc_name {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(env/time/syscall): status={status}");
    eprintln!("compat proof(env/time/syscall): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(env/time/syscall): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat env static set=0 value=env-ok unset=0 missing=<null>"),
        "env fixture did not complete static setenv/getenv/unsetenv; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat proc syscall pid=")
            && !stdout.contains("compat proc syscall pid=0 "),
        "env/time fixture did not print host-backed process identity and raw syscall pid; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat proc libproc static pidpath=")
            && stdout.contains(" path=")
            && stdout.contains("arm64_env_time_compat")
            && stdout.contains(" text=arm64_env_time"),
        "env/time fixture did not complete static proc_pidpath/proc_name host proxy calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat system sysconf_pagesize=")
            && stdout.contains(" gethostname=0 ")
            && stdout.contains(" uname=0 "),
        "env/time fixture did not complete sysconf/gethostname/uname; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat system identity uname_machine=arm64")
            && stdout.contains(" hw_machine=arm64 ")
            && stdout.contains(" arm64=1 "),
        "env/time fixture did not expose ARM guest identity through uname/sysctlbyname; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("\"Kind\":\"identity\"")
            && stderr.contains("\"Call\":\"uname\"")
            && stderr.contains("\"GuestMachine\":\"arm64\"")
            && stderr.contains("\"Call\":\"sysctlbyname\"")
            && stderr.contains("\"Query\":\"hw.machine\"")
            && stderr.contains("\"GuestValueHex\":\"61726D363400\"")
            && stderr.contains("\"GuestValueBytes\":\"6\"")
            && stderr.contains("\"Call\":\"proc_pidpath\"")
            && stderr.contains("\"Call\":\"proc_name\"")
            && stderr.contains("\"Model\":\"host-libproc+guest-self-override\"")
            && stderr.contains("\"HostText\""),
        "verbose compat log did not include guest-facing OS identity payloads; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("compat time imported gtod=0 clock=0 nanosleep=0 usleep=0 sleep=0")
            && stdout.contains("compat time syscall ret=0")
            && stdout.contains("compat time timebase ret=0 numer="),
        "env/time fixture did not complete imported and raw-syscall time probes; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat rlimit syscall ret=0") && stdout.contains(" imported=0"),
        "env/time fixture did not complete imported and raw-syscall getrlimit; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat sysctl syscall ret=0")
            && stdout.contains(" page=")
            && stdout.contains(" byname=0"),
        "env/time fixture did not complete sysctlbyname and raw sysctl; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat envtime dlsym ptrs env=0x")
            && stdout.contains(" pid=0x")
            && stdout.contains(" proc_pidpath=0x")
            && stdout.contains(" proc_name=0x")
            && stdout.contains(" time=0x"),
        "env/time fixture did not receive dlsym trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat proc libproc dlsym pidpath=")
            && stdout.contains("arm64_env_time_compat")
            && stdout.contains(" text=arm64_env_time"),
        "env/time fixture did not complete dlsym proc_pidpath/proc_name host proxy calls; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat envtime dlsym env set=0 value=dyn-ok unset=0")
            && stdout.contains(" gtod=0 clock=0 nanosleep=0 ")
            && stdout.contains(" rlimit=0 sysconf=")
            && stdout.contains(" sysctl=0 page="),
        "env/time fixture did not complete dynamic env/time/resource/sysctl calls; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_keeps_usleep_cooperative_when_guest_threads_are_runnable() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode pthread scheduler test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_pthread_scheduler_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_MAX_INSTRUCTIONS", "3000000")
        .env("COMPATRA_TIMEOUT_USECS", "5000000")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(pthread scheduler): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(pthread scheduler): status={status}");
    eprintln!("compat proof(pthread scheduler): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(pthread scheduler): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("[THREAD][arm64] usleep yield"),
        "pthread scheduler fixture did not yield from _usleep while guest threads were runnable; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat pthread scheduler ready=1"),
        "pthread scheduler fixture did not reach the signaling worker; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_runs_dispatch_and_runloop_startup_glue() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode dispatch/runloop test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let fixture = compile_arm64_dispatch_runloop_fixture();
    let compatra = compatra_binary();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(dispatch/runloop): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(dispatch/runloop): status={status}");
    eprintln!("compat proof(dispatch/runloop): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(dispatch/runloop): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dispatch static ")
                && line.contains(" once=1 ")
                && line.contains(" sync=2 ")
                && line.contains(" async=3 ")
                && line.contains(" context=15 ")
                && line.contains(" run=3 ")
                && line.contains(" pass=1")
        }),
        "dispatch fixture did not execute static blocks/functions inline; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dispatch dlsym ptrs main=")
            && stdout.contains(" global=0x")
            && stdout.contains(" create=0x")
            && stdout.contains(" async=0x")
            && stdout.contains(" sync=0x")
            && stdout.contains(" once=0x")
            && stdout.contains(" async_f=0x")
            && stdout.contains(" sync_f=0x")
            && stdout.contains(" once_f=0x")
            && stdout.contains(" runloop=0x")
            && stdout.contains(" run=0x"),
        "dispatch fixture did not receive dlsym trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dispatch dlsym ")
                && line.contains(" once=1 ")
                && line.contains(" sync=2 ")
                && line.contains(" async=3 ")
                && line.contains(" context=15 ")
                && line.contains(" run=3 ")
                && line.contains(" pass=1")
        }),
        "dispatch fixture did not execute dlsym blocks/functions inline; stdout:\n{stdout}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn compat_mode_proxies_directory_iteration_and_entropy() {
    if std::env::consts::ARCH != "x86_64" {
        eprintln!(
            "skipping Intel macOS compat-mode directory/entropy test on {}",
            std::env::consts::ARCH
        );
        return;
    }

    let (fixture, base_dir) = compile_arm64_directory_entropy_fixture();
    let _ = fs::remove_dir_all(&base_dir);
    let compatra = compatra_binary();
    let scratch_root = generated_fixture_dir_arg();
    let output = Command::new(&compatra)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("COMPATRA_PLUGIN_TRACE", "1")
        .env("COMPATRA_TRACE_FORMAT", "jsonl")
        .env("COMPATRA_PROFILE", "short")
        .env("COMPATRA_DEBUG_STDOUT", "1")
        .env("COMPATRA_ARGV_APPEND", &scratch_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch compatra binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("compatra stdout was not UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let guest_stdout = stdout
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('[')
        })
        .collect::<Vec<_>>()
        .join(" | ");

    eprintln!(
        "compat proof(directory/entropy): command={} --mode compat {}",
        compatra.display(),
        fixture.display()
    );
    eprintln!("compat proof(directory/entropy): status={status}");
    eprintln!("compat proof(directory/entropy): scratch root={scratch_root}");
    eprintln!(
        "compat proof(directory/entropy): base dir={}",
        base_dir.display()
    );
    eprintln!("compat proof(directory/entropy): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(directory/entropy): stderr:\n{stderr}");
    }

    let _ = fs::remove_dir_all(&base_dir);

    assert!(
        status.success(),
        "compatra exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat dir static opendir=0x") && stdout.contains(" dirfd="),
        "directory fixture did not open a host-backed DIR; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir static seen alpha=1 beta=1"),
        "directory fixture did not complete static readdir scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir fdopendir fd=")
            && stdout.contains("compat dir fdopendir seen alpha=1 beta=1"),
        "directory fixture did not complete fdopendir scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir static readdir_r ret=0 alpha=1 beta=1"),
        "directory fixture did not complete static readdir_r scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dir static scandir count=") && line.contains(" alpha=1 beta=1")
        }),
        "directory fixture did not complete static scandir scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dir static glob ret=0") && line.contains(" alpha=1 beta=1")
        }),
        "directory fixture did not complete static glob scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir static getattrlist ret=0 len="),
        "directory fixture did not complete static getattrlist probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat entropy static ret=0 nonzero=1 syscall=0 sc_nonzero=1"),
        "directory fixture did not complete static and raw-syscall getentropy; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir dlsym ptrs opendir=0x")
            && stdout.contains(" readdir=0x")
            && stdout.contains(" scandir=0x")
            && stdout.contains(" glob=0x")
            && stdout.contains(" getattrlist=0x")
            && stdout.contains(" entropy=0x"),
        "directory fixture did not receive dlsym directory/entropy trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir dlsym seen alpha=1 beta=1"),
        "directory fixture did not complete dlsym readdir scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir dlsym readdir_r ret=0 alpha=1 beta=1"),
        "directory fixture did not complete dlsym readdir_r scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dir dlsym scandir count=") && line.contains(" alpha=1 beta=1")
        }),
        "directory fixture did not complete dlsym scandir scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("compat dir dlsym glob ret=0") && line.contains(" alpha=1 beta=1")
        }),
        "directory fixture did not complete dlsym glob scan; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir dlsym getattrlist ret=0 len="),
        "directory fixture did not complete dlsym getattrlist probe; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat entropy dlsym ret=0 nonzero=1"),
        "directory fixture did not complete dlsym getentropy; stdout:\n{stdout}"
    );
}
