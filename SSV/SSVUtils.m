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
    int sandboxRet = patch_sandbox_ext();                    // ← SSV + rootfs r/w
    debug_log("patch_sandbox_ext returned %d", sandboxRet);

    debug_log("Calling overwrite_system_file(%s)", path);
    int ret = overwrite_system_file((char*)path, tmp);
    debug_log("overwrite_system_file returned %d", ret);

    unlink(tmp);
    return ret == 0;
}

bool ssv_chown_root(const char *path) {
    uint64_t vnode = get_vnode_for_path_by_open(path);
    if (vnode == -1) return false;

    uint64_t v_data = kread64(vnode + off_vnode_v_data);
    if (!v_data) return false;

    kwrite32(v_data + 0x80, 0);   // uid = 0 (root)
    kwrite32(v_data + 0x84, 0);   // gid = 0
    kwrite16(v_data + 0x88, 0666); // rw-rw-rw-

    // refresh vnode
    uint32_t usec = kread32(vnode + off_vnode_v_usecount);
    uint32_t ioc  = kread32(vnode + off_vnode_v_iocount);
    kwrite32(vnode + off_vnode_v_usecount, usec + 1);
    kwrite32(vnode + off_vnode_v_iocount,  ioc  + 1);
    kwrite32(vnode + off_vnode_v_usecount, usec);
    kwrite32(vnode + off_vnode_v_iocount,  ioc);

    return true;
}

void ssv_dump_fsnode(const char *path) {
    research_vnode_apfs_fsnode(path);
}
