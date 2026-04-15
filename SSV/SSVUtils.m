#import "SSVUtils.h"
#import <stdbool.h>
#import <unistd.h>
#import <fcntl.h>
#import <time.h>
#import <stdarg.h>
#import <limits.h>
#import <dispatch/dispatch.h>
#import "kexploit/krw.h"
#import "kexploit/vnode.h"
#import "kexploit/kutils.h"
#import "kexploit/sandbox.h"
#import "kexploit/file.h"
#import "kexploit/vnode_research.h"
#import "utils/permission_utils.h"

static const char *getSSVLogPath(void) {
    static char path[PATH_MAX];
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *tmp = NSTemporaryDirectory();
        if (!tmp || tmp.length == 0) tmp = @"/tmp";
        NSString *file = [tmp stringByAppendingPathComponent:@"FilzaSSVDebug.log"];
        const char *cpath = [file fileSystemRepresentation];
        strlcpy(path, cpath, sizeof(path));
    });
    return path;
}

static void debug_log(const char *format, ...) {
    const char *logPath = getSSVLogPath();
    FILE *logFile = fopen(logPath, "a");
    if (logFile == NULL) {
        fprintf(stderr, "[SSVUtils] Cannot open log file at %s\n", logPath);
        return;
    }
    
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(logFile, "[%s] ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(logFile, format, args);
    va_end(args);
    
    fprintf(logFile, "\n");
    fflush(logFile);
    fclose(logFile);
}

__attribute__((constructor))
static void SSVUtils_init(void) {
    debug_log("SSVUtils loaded successfully");
}

bool ssv_write(const char *path, const void *data, size_t len) {
    debug_log("ssv_write called with path: %s", path);
    if (!data || len == 0) return false;

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "/tmp/ssv_%d", getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    write(fd, data, len);
    close(fd);

    debug_log("Calling patch_sandbox_ext()...");
    int sandboxRet = patch_sandbox_ext();
    debug_log("patch_sandbox_ext returned %d", sandboxRet);

    bool isSSV = is_ssv_protected_path(path);
    debug_log("Path %s is SSV-protected: %s", path, isSSV ? "YES" : "NO");

    int ret = -1;
    if (isSSV) {
        debug_log("Using overwrite_system_file for SSV path");
        ret = overwrite_system_file((char*)path, tmp);
        if (ret == 0) {
            debug_log("SSV write successful, applying root:wheel");
            force_chown_root_wheel(path);
        }
    } else {
        debug_log("Using standard copy for non-SSV path");
        if (rename(tmp, path) == 0) {
            ret = 0;
            debug_log("Non-SSV write successful, applying parent permissions");
            apply_parent_permissions(path);
        } else {
            debug_log("rename failed: %s", strerror(errno));
            int fd_in = open(tmp, O_RDONLY);
            int fd_out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in >= 0 && fd_out >= 0) {
                char buf[4096];
                ssize_t n;
                while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
                    write(fd_out, buf, n);
                }
                close(fd_in);
                close(fd_out);
                ret = 0;
                apply_parent_permissions(path);
            }
        }
    }

    debug_log("Final result: %d", ret);
    unlink(tmp);
    return ret == 0;
}

bool ssv_chown_root(const char *path) {
    debug_log("ssv_chown_root called for: %s", path);
    return force_chown_root_wheel(path);
}

void ssv_dump_fsnode(const char *path) {
    research_vnode_apfs_fsnode(path);
}
