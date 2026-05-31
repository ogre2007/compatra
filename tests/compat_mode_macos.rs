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
}

#[cfg(target_os = "macos")]
fn fixture_path() -> PathBuf {
    workspace_root().join(HELLO_FIXTURE)
}

#[cfg(target_os = "macos")]
fn machina_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_machina"))
}

#[cfg(target_os = "macos")]
fn generated_fixture_dir() -> PathBuf {
    workspace_root()
        .join("target")
        .join("machina-compat-fixtures")
}

#[cfg(target_os = "macos")]
fn c_string_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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

typedef void *(*malloc_fn)(size_t);
typedef void *(*calloc_fn)(size_t, size_t);
typedef void *(*realloc_fn)(void *, size_t);
typedef void (*free_fn)(void *);
typedef int (*posix_memalign_fn)(void **, size_t, size_t);
typedef void *(*memcpy_fn)(void *, const void *, size_t);
typedef void *(*memmove_fn)(void *, const void *, size_t);
typedef void *(*memset_fn)(void *, int, size_t);
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
        && memcmp_eq == 0
        && len == 5
        && cmp_eq == 0
        && cmp_lt < 0
        && ncmp == 0
        && hit_off == 4
        && last_off == 9;

    printf(
        "compat memstr %s dst=%s overlap=%s copy=%s dup=%s heap=%s zero_ok=%d pa=%d aligned_mod=%lu memcmp=%d len=%lu cmp=%d cmp_lt=%d ncmp=%d hit=%ld last=%ld ok=%d\n",
        label,
        dst,
        overlap,
        copy,
        dup ? dup : "<null>",
        heap ? heap : "<null>",
        zero_ok,
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

    void *self = dlopen(NULL, RTLD_NOW);
    malloc_fn dyn_malloc = (malloc_fn)dlsym(self, "malloc");
    calloc_fn dyn_calloc = (calloc_fn)dlsym(self, "calloc");
    realloc_fn dyn_realloc = (realloc_fn)dlsym(self, "realloc");
    free_fn dyn_free = (free_fn)dlsym(self, "free");
    posix_memalign_fn dyn_posix_memalign = (posix_memalign_fn)dlsym(self, "posix_memalign");
    memcpy_fn dyn_memcpy = (memcpy_fn)dlsym(self, "memcpy");
    memmove_fn dyn_memmove = (memmove_fn)dlsym(self, "memmove");
    memset_fn dyn_memset = (memset_fn)dlsym(self, "memset");
    memcmp_fn dyn_memcmp = (memcmp_fn)dlsym(self, "memcmp");
    strlen_fn dyn_strlen = (strlen_fn)dlsym(self, "strlen");
    strcmp_fn dyn_strcmp = (strcmp_fn)dlsym(self, "strcmp");
    strncmp_fn dyn_strncmp = (strncmp_fn)dlsym(self, "strncmp");
    strcpy_fn dyn_strcpy = (strcpy_fn)dlsym(self, "strcpy");
    strncpy_fn dyn_strncpy = (strncpy_fn)dlsym(self, "strncpy");
    strcat_fn dyn_strcat = (strcat_fn)dlsym(self, "strcat");
    strchr_fn dyn_strchr = (strchr_fn)dlsym(self, "strchr");
    strrchr_fn dyn_strrchr = (strrchr_fn)dlsym(self, "strrchr");
    strdup_fn dyn_strdup = (strdup_fn)dlsym(self, "strdup");
    printf(
        "compat memstr dlsym ptrs malloc=%p free=%p memcpy=%p strcmp=%p strcpy=%p strchr=%p strdup=%p posix_memalign=%p\n",
        (void *)dyn_malloc,
        (void *)dyn_free,
        (void *)dyn_memcpy,
        (void *)dyn_strcmp,
        (void *)dyn_strcpy,
        (void *)dyn_strchr,
        (void *)dyn_strdup,
        (void *)dyn_posix_memalign
    );
    if (!dyn_malloc || !dyn_calloc || !dyn_realloc || !dyn_free || !dyn_posix_memalign || !dyn_memcpy || !dyn_memmove || !dyn_memset || !dyn_memcmp || !dyn_strlen || !dyn_strcmp || !dyn_strncmp || !dyn_strcpy || !dyn_strncpy || !dyn_strcat || !dyn_strchr || !dyn_strrchr || !dyn_strdup) {
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
fn compile_arm64_network_fixture() -> PathBuf {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_network_compat.c");
    let binary = out_dir.join("arm64_network_compat");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef void (*freeaddrinfo_fn)(struct addrinfo *);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);

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

int main(void) {
    int failures = 0;
    failures += probe_gai("static", getaddrinfo, freeaddrinfo);
    failures += probe_msg("static", sendmsg, recvmsg);

    void *self = dlopen(NULL, RTLD_NOW);
    getaddrinfo_fn dyn_gai = (getaddrinfo_fn)dlsym(self, "getaddrinfo");
    freeaddrinfo_fn dyn_free = (freeaddrinfo_fn)dlsym(self, "freeaddrinfo");
    send_fn dyn_send = (send_fn)dlsym(self, "send");
    recv_fn dyn_recv = (recv_fn)dlsym(self, "recv");
    sendmsg_fn dyn_sendmsg = (sendmsg_fn)dlsym(self, "sendmsg");
    recvmsg_fn dyn_recvmsg = (recvmsg_fn)dlsym(self, "recvmsg");
    printf(
        "compat dlsym network ptrs %p %p %p %p %p %p\n",
        (void *)dyn_gai,
        (void *)dyn_free,
        (void *)dyn_send,
        (void *)dyn_recv,
        (void *)dyn_sendmsg,
        (void *)dyn_recvmsg
    );
    if (dyn_gai == 0 || dyn_free == 0 || dyn_send == 0 || dyn_recv == 0 || dyn_sendmsg == 0 || dyn_recvmsg == 0) {
        return 4;
    }
    failures += probe_gai("dlsym", dyn_gai, dyn_free);
    failures += probe_msg("dlsym", dyn_sendmsg, dyn_recvmsg);

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
fn compile_arm64_fd_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_fd_compat.c");
    let binary = out_dir.join("arm64_fd_compat");
    let data_file = out_dir.join("arm64_fd_compat.tmp");
    let data_dir_literal = c_string_literal(&out_dir.display().to_string());
    let data_file_literal = c_string_literal(&data_file.display().to_string());
    let data_name_literal = c_string_literal(
        data_file
            .file_name()
            .expect("generated data file has a file name")
            .to_string_lossy()
            .as_ref(),
    );
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
#define DATA_DIR "{data_dir_literal}"
#define DATA_FILE "{data_file_literal}"
#define DATA_NAME "{data_name_literal}"
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

static long machina_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
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

static long machina_pipe_syscall(int fds[2]) {{
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

int main(void) {{
    int failures = 0;
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

    int file_fd = open(DATA_FILE, O_CREAT | O_TRUNC | O_RDWR, 0600);
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
    int statfs_ret = statfs(DATA_FILE, &path_fs);
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

    long raw_fd = machina_syscall6(SYS_OPEN_NOCANCEL, (long)DATA_FILE, O_RDWR, 0600, 0, 0, 0);
    const char raw_text[] = "nc-ok";
    long raw_write = raw_fd >= 0 ? machina_syscall6(SYS_WRITE_NOCANCEL, raw_fd, (long)raw_text, 5, 0, 0, 0) : -1;
    long raw_seek = raw_fd >= 0 ? (long)lseek((int)raw_fd, 0, SEEK_SET) : -1;
    char raw_buf[8] = {{0}};
    long raw_read = raw_fd >= 0 ? machina_syscall6(SYS_READ_NOCANCEL, raw_fd, (long)raw_buf, 5, 0, 0, 0) : -1;
    long raw_fcntl = raw_fd >= 0 ? machina_syscall6(SYS_FCNTL_NOCANCEL, raw_fd, F_GETFD, 0, 0, 0, 0) : -1;
    long raw_close = raw_fd >= 0 ? machina_syscall6(SYS_CLOSE_NOCANCEL, raw_fd, 0, 0, 0, 0, 0) : -1;
    printf("compat fd nocancel io open=%ld write=%ld seek=%ld read=%ld errno=%d\n", raw_fd, raw_write, raw_seek, raw_read, errno);
    printf("compat fd nocancel result text=%s fcntl=%ld close=%ld errno=%d\n", raw_buf, raw_fcntl, raw_close, errno);
    if (raw_fd < 0 || raw_write != 5 || raw_seek != 0 || raw_read != 5 || !text_is(raw_buf, "nc-ok", 5) || raw_fcntl < 0 || raw_close != 0) {{
        failures += 45;
    }}

    int raw_pipe_fds[2] = {{-1, -1}};
    long raw_pipe = machina_pipe_syscall(raw_pipe_fds);
    int raw_available = -1;
    if (raw_pipe == 0) {{
        write(raw_pipe_fds[1], "RP", 2);
    }}
    long raw_ioctl = raw_pipe == 0 ? machina_syscall6(SYS_IOCTL, raw_pipe_fds[0], FIONREAD, (long)&raw_available, 0, 0, 0) : -1;
    char raw_pipe_buf[4] = {{0}};
    if (raw_pipe == 0) {{
        read(raw_pipe_fds[0], raw_pipe_buf, 2);
        close(raw_pipe_fds[0]);
        close(raw_pipe_fds[1]);
    }}
    long raw_fsync = file_fd >= 0 ? machina_syscall6(SYS_FSYNC, file_fd, 0, 0, 0, 0, 0) : -1;
    struct statfs raw_path_fs = {{0}};
    struct statfs raw_fd_fs = {{0}};
    long raw_statfs = machina_syscall6(SYS_STATFS64, (long)DATA_FILE, (long)&raw_path_fs, 0, 0, 0, 0);
    long raw_fstatfs = file_fd >= 0 ? machina_syscall6(SYS_FSTATFS64, file_fd, (long)&raw_fd_fs, 0, 0, 0, 0) : -1;
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

    int dir_fd = open(DATA_DIR, O_RDONLY);
    long raw_openat = dir_fd >= 0 ? machina_syscall6(SYS_OPENAT, dir_fd, (long)DATA_NAME, O_RDONLY, 0, 0, 0) : -1;
    long raw_faccessat = dir_fd >= 0 ? machina_syscall6(SYS_FACCESSAT, dir_fd, (long)DATA_NAME, R_OK, 0, 0, 0) : -1;
    struct stat raw_at_stat = {{0}};
    long raw_fstatat = dir_fd >= 0 ? machina_syscall6(SYS_FSTATAT, dir_fd, (long)DATA_NAME, (long)&raw_at_stat, 0, 0, 0) : -1;
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

    int dyn_rw_fd = dyn_open(DATA_FILE, O_CREAT | O_TRUNC | O_RDWR, 0600);
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
    let data_file_literal = c_string_literal(&data_file.display().to_string());
    fs::write(
        &source,
        format!(
            r#"#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DATA_FILE "{data_file_literal}"

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

static int stdio_roundtrip(
    const char *label,
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
    FILE *stream = fopen_impl(DATA_FILE, "w+");
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

    int raw_fd = open(DATA_FILE, O_RDONLY);
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

int main(void) {{
    int failures = 0;
    failures += stdio_roundtrip("static", fopen, fdopen, fclose, fread, fwrite, fflush, fseek, ftell, fgets, fputs, feof, ferror, clearerr, fileno);

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
    failures += stdio_roundtrip("dlsym", dyn_fopen, dyn_fdopen, dyn_fclose, dyn_fread, dyn_fwrite, dyn_fflush, dyn_fseek, dyn_ftell, dyn_fgets, dyn_fputs, dyn_feof, dyn_ferror, dyn_clearerr, dyn_fileno);
    dlclose(self);
    unlink(DATA_FILE);
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
    let base_dir_literal = c_string_literal(&base_dir.display().to_string());
    fs::write(
        &source,
        format!(
            r#"#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BASE_DIR "{base_dir_literal}"
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

extern char *realpath(const char *, char *);

static long machina_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
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

static void cleanup_base(void) {{
    unlink(BASE_DIR "/alpha.txt");
    unlink(BASE_DIR "/beta.txt");
    unlink(BASE_DIR "/alpha.link");
    unlink(BASE_DIR "/raw-at.txt");
    unlink(BASE_DIR "/raw-new.txt");
    unlink(BASE_DIR "/raw.link");
    unlink(BASE_DIR "/dyn-old.txt");
    unlink(BASE_DIR "/dyn-new.txt");
    unlink(BASE_DIR "/dyn.link");
    unlink(BASE_DIR "/dyn-mode.txt");
    unlink(BASE_DIR "/dyn-at.txt");
    unlink(BASE_DIR "/dyn-at-new.txt");
    unlink(BASE_DIR "/dyn-at.link");
    rmdir(BASE_DIR "/raw-dir");
    rmdir(BASE_DIR "/dyn-dir");
    rmdir(BASE_DIR "/dyn-at-dir");
    rmdir(BASE_DIR "/empty");
    rmdir(BASE_DIR);
}}

int main(void) {{
    int failures = 0;
    cleanup_base();
    int mkdir_base = mkdir(BASE_DIR, 0700);
    int chdir_base = chdir(BASE_DIR);
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
    if (fd < 0 || chmod_ret != 0 || fchmod_ret != 0 || truncate_ret != 0 || ftruncate_ret != 0 || access_ret != 0 || stat_ret != 0 || st.st_size != 5 || fstat_ret != 0 || fst.st_size != 5 || symlink_ret != 0 || readlink_ret != 9 || !text_is(link_target, "alpha.txt") || lstat_ret != 0 || realpath_ret == 0) {{
        failures += 20;
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
    long raw_chmod = machina_syscall6(SYS_CHMOD, (long)"raw-at.txt", 0644, 0, 0, 0, 0);
    long raw_fchmod = machina_syscall6(SYS_FCHMOD, raw_fd, 0600, 0, 0, 0, 0);
    long raw_fchmodat = machina_syscall6(SYS_FCHMODAT, AT_FDCWD, (long)"raw-at.txt", 0644, 0, 0, 0);
    long raw_truncate = machina_syscall6(SYS_TRUNCATE, (long)"raw-at.txt", 3, 0, 0, 0, 0);
    long raw_ftruncate = machina_syscall6(SYS_FTRUNCATE, raw_fd, 4, 0, 0, 0, 0);
    struct stat raw_st = {{0}};
    stat("raw-at.txt", &raw_st);
    long raw_mkdirat = machina_syscall6(SYS_MKDIRAT, AT_FDCWD, (long)"raw-dir", 0700, 0, 0, 0);
    long raw_renameat = machina_syscall6(SYS_RENAMEAT, AT_FDCWD, (long)"raw-at.txt", AT_FDCWD, (long)"raw-new.txt", 0, 0);
    int raw_symlink = symlink("raw-new.txt", "raw.link");
    char raw_link_target[128] = {{0}};
    long raw_readlinkat = machina_syscall6(SYS_READLINKAT, AT_FDCWD, (long)"raw.link", (long)raw_link_target, sizeof(raw_link_target) - 1, 0, 0);
    if (raw_readlinkat >= 0 && raw_readlinkat < (long)sizeof(raw_link_target)) {{
        raw_link_target[raw_readlinkat] = 0;
    }}
    long raw_unlinkat = machina_syscall6(SYS_UNLINKAT, AT_FDCWD, (long)"raw-new.txt", 0, 0, 0, 0);
    long raw_unlinkat_link = machina_syscall6(SYS_UNLINKAT, AT_FDCWD, (long)"raw.link", 0, 0, 0, 0);
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
    if (!dyn_access || !dyn_chmod || !dyn_fchmod || !dyn_fchmodat || !dyn_chdir || !dyn_getcwd || !dyn_stat || !dyn_lstat || !dyn_fstat || !dyn_truncate || !dyn_ftruncate || !dyn_mkdir || !dyn_mkdirat || !dyn_rmdir || !dyn_unlink || !dyn_unlinkat || !dyn_rename || !dyn_renameat || !dyn_readlink || !dyn_readlinkat || !dyn_symlink || !dyn_realpath) {{
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
    if (dyn_fd < 0 || dyn_rename_ret != 0 || dyn_access_ret != 0 || dyn_stat_ret != 0 || dyn_st.st_size != 7 || dyn_fstat_ret != 0 || dyn_fst.st_size != 7 || dyn_symlink_ret != 0 || dyn_readlink_ret != 11 || !text_is(dyn_link_target, "dyn-new.txt") || dyn_lstat_ret != 0 || dyn_realpath_ret == 0) {{
        failures += 60;
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
    rmdir(BASE_DIR);
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
typedef int (*gettimeofday_fn)(struct timeval *, void *);
typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*nanosleep_fn)(const struct timespec *, struct timespec *);
typedef uint64_t (*mach_absolute_time_fn)(void);
typedef kern_return_t (*mach_timebase_info_fn)(mach_timebase_info_t);
typedef int (*getrlimit_fn)(int, struct rlimit *);
typedef long (*sysconf_fn)(int);
typedef int (*sysctlbyname_fn)(const char *, void *, size_t *, void *, size_t);

static long machina_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {
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

    int set_ret = setenv("MACHINA_COMPAT_ENV", "env-ok", 1);
    char *value = getenv("MACHINA_COMPAT_ENV");
    int unset_ret = unsetenv("MACHINA_COMPAT_ENV");
    char *missing = getenv("MACHINA_COMPAT_ENV");
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
    long syscall_pid = machina_syscall6(0x2000014, 0, 0, 0, 0, 0, 0);
    printf("compat proc ids pid=%d ppid=%d uid=%u euid=%u gid=%u egid=%u syscall_pid=%ld\n", pid, ppid, uid, euid, gid, egid, syscall_pid);
    printf("compat proc syscall pid=%ld host_pid=%d\n", syscall_pid, pid);
    if (pid <= 0 || syscall_pid <= 0) {
        failures += 20;
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

    struct timeval tv = {0};
    int gtod_ret = gettimeofday(&tv, 0);
    struct timeval syscall_tv = {0};
    uint64_t syscall_mach = 0;
    long syscall_gtod = machina_syscall6(0x2000074, (long)&syscall_tv, 0, (long)&syscall_mach, 0, 0, 0);
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
    long syscall_rlimit = machina_syscall6(0x20000C2, RLIMIT_NOFILE, (long)&syscall_lim, 0, 0, 0, 0);
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
    long syscall_sysctl = machina_syscall6(0x20000CA, (long)mib, 2, (long)&syscall_page, (long)&syscall_page_len, 0, 0);
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
    gettimeofday_fn dyn_gettimeofday = (gettimeofday_fn)dlsym(self, "gettimeofday");
    clock_gettime_fn dyn_clock_gettime = (clock_gettime_fn)dlsym(self, "clock_gettime");
    nanosleep_fn dyn_nanosleep = (nanosleep_fn)dlsym(self, "nanosleep");
    mach_absolute_time_fn dyn_mach_absolute_time = (mach_absolute_time_fn)dlsym(self, "mach_absolute_time");
    mach_timebase_info_fn dyn_mach_timebase_info = (mach_timebase_info_fn)dlsym(self, "mach_timebase_info");
    getrlimit_fn dyn_getrlimit = (getrlimit_fn)dlsym(self, "getrlimit");
    sysconf_fn dyn_sysconf = (sysconf_fn)dlsym(self, "sysconf");
    sysctlbyname_fn dyn_sysctlbyname = (sysctlbyname_fn)dlsym(self, "sysctlbyname");
    printf("compat envtime dlsym ptrs env=%p pid=%p time=%p rlimit=%p sysctl=%p\n", (void *)dyn_getenv, (void *)dyn_getpid, (void *)dyn_gettimeofday, (void *)dyn_getrlimit, (void *)dyn_sysctlbyname);
    if (!dyn_getenv || !dyn_setenv || !dyn_unsetenv || !dyn_getpid || !dyn_gettimeofday || !dyn_clock_gettime || !dyn_nanosleep || !dyn_mach_absolute_time || !dyn_mach_timebase_info || !dyn_getrlimit || !dyn_sysconf || !dyn_sysctlbyname) {
        return 70;
    }

    int dyn_set = dyn_setenv("MACHINA_COMPAT_DYN_ENV", "dyn-ok", 1);
    char *dyn_env = dyn_getenv("MACHINA_COMPAT_DYN_ENV");
    int dyn_unset = dyn_unsetenv("MACHINA_COMPAT_DYN_ENV");
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
    if (dyn_set != 0 || dyn_env == 0 || dyn_env[0] != 'd' || dyn_unset != 0 || dyn_getpid() <= 0 || dyn_gtod != 0 || dyn_clock != 0 || dyn_nano != 0 || dyn_mach == 0 || dyn_timebase_ret != 0 || dyn_timebase.numer == 0 || dyn_timebase.denom == 0 || dyn_rlimit != 0 || dyn_page <= 0 || dyn_byname != 0 || dyn_byname_page <= 0) {
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
fn compile_arm64_directory_entropy_fixture() -> (PathBuf, PathBuf) {
    let out_dir = generated_fixture_dir();
    fs::create_dir_all(&out_dir).expect("failed to create generated fixture directory");
    let source = out_dir.join("arm64_directory_entropy_compat.c");
    let binary = out_dir.join("arm64_directory_entropy_compat");
    let base_dir = out_dir.join("dir-host-root");
    let base_dir_literal = c_string_literal(&base_dir.display().to_string());
    let alpha_file_literal = c_string_literal(&base_dir.join("alpha.txt").display().to_string());
    let beta_file_literal = c_string_literal(&base_dir.join("beta.txt").display().to_string());
    fs::write(
        &source,
        format!(
            r#"#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define BASE_DIR "{base_dir_literal}"
#define ALPHA_FILE "{alpha_file_literal}"
#define BETA_FILE "{beta_file_literal}"

typedef DIR *(*opendir_fn)(const char *);
typedef DIR *(*fdopendir_fn)(int);
typedef struct dirent *(*readdir_fn)(DIR *);
typedef int (*readdir_r_fn)(DIR *, struct dirent *, struct dirent **);
typedef int (*closedir_fn)(DIR *);
typedef int (*dirfd_fn)(DIR *);
typedef void (*rewinddir_fn)(DIR *);
typedef long (*telldir_fn)(DIR *);
typedef void (*seekdir_fn)(DIR *, long);
typedef int (*getentropy_fn)(void *, size_t);

extern int getentropy(void *, size_t);

static long machina_syscall6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {{
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

int main(void) {{
    int failures = 0;
    mkdir(BASE_DIR, 0700);
    write_file(ALPHA_FILE, "a");
    write_file(BETA_FILE, "b");

    DIR *dir = opendir(BASE_DIR);
    int static_fd = dir ? dirfd(dir) : -1;
    printf("compat dir static opendir=%p dirfd=%d errno=%d\n", dir, static_fd, errno);
    if (!dir || static_fd < 0) {{
        return 10;
    }}
    failures += scan_with_readdir("static", dir, readdir, rewinddir, telldir, seekdir);
    closedir(dir);

    int fd = open(BASE_DIR, O_RDONLY);
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

    DIR *rr_dir = opendir(BASE_DIR);
    failures += rr_dir ? scan_with_readdir_r("static", rr_dir, readdir_r) : 30;
    if (rr_dir) {{
        closedir(rr_dir);
    }}

    unsigned char entropy[16] = {{0}};
    int entropy_ret = getentropy(entropy, sizeof(entropy));
    unsigned char syscall_entropy[16] = {{0}};
    long syscall_entropy_ret = machina_syscall6(0x20001F4, (long)syscall_entropy, sizeof(syscall_entropy), 0, 0, 0, 0);
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
    getentropy_fn dyn_getentropy = (getentropy_fn)dlsym(self, "getentropy");
    printf("compat dir dlsym ptrs opendir=%p readdir=%p closedir=%p dirfd=%p entropy=%p\n", (void *)dyn_opendir, (void *)dyn_readdir, (void *)dyn_closedir, (void *)dyn_dirfd, (void *)dyn_getentropy);
    if (!dyn_opendir || !dyn_fdopendir || !dyn_readdir || !dyn_readdir_r || !dyn_closedir || !dyn_dirfd || !dyn_rewinddir || !dyn_telldir || !dyn_seekdir || !dyn_getentropy) {{
        return 50;
    }}

    DIR *dyn_dir = dyn_opendir(BASE_DIR);
    int dyn_fd = dyn_dir ? dyn_dirfd(dyn_dir) : -1;
    printf("compat dir dlsym opendir=%p dirfd=%d errno=%d\n", dyn_dir, dyn_fd, errno);
    failures += dyn_dir ? scan_with_readdir("dlsym", dyn_dir, dyn_readdir, dyn_rewinddir, dyn_telldir, dyn_seekdir) : 60;
    if (dyn_dir) {{
        dyn_closedir(dyn_dir);
    }}

    int dyn_raw_fd = open(BASE_DIR, O_RDONLY);
    DIR *dyn_fd_dir = dyn_fdopendir(dyn_raw_fd);
    failures += dyn_fd_dir ? scan_with_readdir_r("dlsym", dyn_fd_dir, dyn_readdir_r) : 70;
    if (dyn_fd_dir) {{
        dyn_closedir(dyn_fd_dir);
    }} else if (dyn_raw_fd >= 0) {{
        close(dyn_raw_fd);
    }}

    unsigned char dyn_entropy[16] = {{0}};
    int dyn_entropy_ret = dyn_getentropy(dyn_entropy, sizeof(dyn_entropy));
    printf("compat entropy dlsym ret=%d nonzero=%d errno=%d\n", dyn_entropy_ret, any_nonzero(dyn_entropy, sizeof(dyn_entropy)), errno);
    if (dyn_entropy_ret != 0 || !any_nonzero(dyn_entropy, sizeof(dyn_entropy))) {{
        failures += 80;
    }}

    dlclose(self);
    unlink(ALPHA_FILE);
    unlink(BETA_FILE);
    rmdir(BASE_DIR);
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

    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        // The compat trace bus intentionally has no analysis plugin preset,
        // so enable legacy startup diagnostics only for this smoke test. These
        // markers prove Unicorn entered guest arm64 code and returned through
        // the synthetic done address instead of merely accepting the CLI input.
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
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
        "machina exited with non-zero status {:?}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        "compat proof(write+dlsym): command={} --mode compat {}",
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(write+dlsym): status={status}");
    eprintln!("compat proof(write+dlsym): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(write+dlsym): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(memory/string): status={status}");
    eprintln!("compat proof(memory/string): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(memory/string): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
        status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("compat memstr static dst=alpha")
            && stdout.contains("overlap=ababcd")
            && stdout.contains("heap=heap-ok")
            && stdout.contains("zero_ok=1")
            && stdout.contains("aligned_mod=0")
            && stdout.contains("hit=4 last=9 ok=1"),
        "memory/string fixture did not complete static import roundtrip; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr dlsym ptrs malloc=0x")
            && stdout.contains(" memcpy=0x")
            && stdout.contains(" strcmp=0x")
            && stdout.contains(" strdup=0x")
            && stdout.contains(" posix_memalign=0x"),
        "memory/string fixture did not receive dlsym memory/string trampolines; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat memstr dlsym dst=alpha")
            && stdout.contains("overlap=ababcd")
            && stdout.contains("heap=heap-ok")
            && stdout.contains("zero_ok=1")
            && stdout.contains("aligned_mod=0")
            && stdout.contains("hit=4 last=9 ok=1"),
        "memory/string fixture did not complete dynamic import roundtrip; stdout:\n{stdout}"
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(network): status={status}");
    eprintln!("compat proof(network): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(network): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
        stdout.contains("compat dlsym network ptrs 0x"),
        "network fixture did not receive dlsym trampolines; stdout:\n{stdout}"
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(fd): status={status}");
    eprintln!("compat proof(fd): data file={}", data_file.display());
    eprintln!("compat proof(fd): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(fd): stderr:\n{stderr}");
    }

    let _ = fs::remove_file(&data_file);

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(stdio): status={status}");
    eprintln!("compat proof(stdio): data file={}", data_file.display());
    eprintln!("compat proof(stdio): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(stdio): stderr:\n{stderr}");
    }

    let _ = fs::remove_file(&data_file);

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(path): status={status}");
    eprintln!("compat proof(path): base dir={}", base_dir.display());
    eprintln!("compat proof(path): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(path): stderr:\n{stderr}");
    }

    let _ = fs::remove_dir_all(&base_dir);

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        "compat proof(env/time/syscall): command={} --mode compat {}",
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(env/time/syscall): status={status}");
    eprintln!("compat proof(env/time/syscall): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(env/time/syscall): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
        stdout.contains("compat system sysconf_pagesize=")
            && stdout.contains(" gethostname=0 ")
            && stdout.contains(" uname=0 "),
        "env/time fixture did not complete sysconf/gethostname/uname; stdout:\n{stdout}"
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
            && stdout.contains(" time=0x"),
        "env/time fixture did not receive dlsym trampolines; stdout:\n{stdout}"
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_MAX_INSTRUCTIONS", "3000000")
        .env("MACHINA_TIMEOUT_USECS", "5000000")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(pthread scheduler): status={status}");
    eprintln!("compat proof(pthread scheduler): guest stdout={guest_stdout:?}");
    if !stderr.trim().is_empty() {
        eprintln!("compat proof(pthread scheduler): stderr:\n{stderr}");
    }

    assert!(
        status.success(),
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
    let machina = machina_binary();
    let output = Command::new(&machina)
        .arg("--mode")
        .arg("compat")
        .arg(&fixture)
        .env("MACHINA_PLUGIN_TRACE", "1")
        .env("MACHINA_TRACE_FORMAT", "jsonl")
        .env("MACHINA_PROFILE", "short")
        .env("MACHINA_DEBUG_STDOUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to launch machina binary");

    let status = output.status;
    let stdout = String::from_utf8(output.stdout).expect("machina stdout was not UTF-8");
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
        machina.display(),
        fixture.display()
    );
    eprintln!("compat proof(directory/entropy): status={status}");
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
        "machina exited with non-zero status {:?}\nstdout:\n{}\nstderr:\n{}",
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
        stdout.contains("compat entropy static ret=0 nonzero=1 syscall=0 sc_nonzero=1"),
        "directory fixture did not complete static and raw-syscall getentropy; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("compat dir dlsym ptrs opendir=0x")
            && stdout.contains(" readdir=0x")
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
        stdout.contains("compat entropy dlsym ret=0 nonzero=1"),
        "directory fixture did not complete dlsym getentropy; stdout:\n{stdout}"
    );
}
