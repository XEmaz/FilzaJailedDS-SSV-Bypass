#ifndef SSVUtils_h
#define SSVUtils_h

#import <Foundation/Foundation.h>
#import <stdbool.h>
#import <stddef.h>

#import "kexploit/sandbox.h"
#import "kexploit/file.h"

bool ssv_write(const char *path, const void *data, size_t len);
bool ssv_chown_root(const char *path);
void ssv_dump_fsnode(const char *path); // debug

#endif
