// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define MAX_NAME_LEN 64


struct blocked_path_t {
    char parent[MAX_NAME_LEN];
    char child[MAX_NAME_LEN];
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct blocked_path_t));
} block_path_map SEC(".maps");



static __inline bool name_equals(const char *s1, const char *s2)
{
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_NAME_LEN; i++) {
        if (s1[i] != s2[i])
            return false;
        if (s1[i] == '\0')
            return true;
    }
    return false;
}

SEC("lsm/inode_create")
int BPF_PROG(block_path_create_ext, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    u32 key = 0;
    struct blocked_path_t *bp = bpf_map_lookup_elem(&block_path_map, &key);
    if (!bp) {
        return 0;
    }

    struct dentry *current = dentry;

#pragma unroll
    for (int depth = 0; depth < 20; depth++) {
        if (!current)
            break;

        char current_name[MAX_NAME_LEN] = {};
        bpf_probe_read_kernel_str(current_name, sizeof(current_name),
                                  BPF_CORE_READ(current, d_name.name));

        if (name_equals(current_name, bp->child)) {
            struct dentry *parent = BPF_CORE_READ(current, d_parent);
            if (!parent)
                break;

            if (bp->parent[0] == '\0') {
                struct dentry *grandp = BPF_CORE_READ(parent, d_parent);
                if (grandp) {
                    struct dentry *ggp = BPF_CORE_READ(grandp, d_parent);
                    if (ggp == grandp) {
                        // => /child => 
                        return -EPERM;
                    }
                }
            } else {
                char parent_name[MAX_NAME_LEN] = {};
                bpf_probe_read_kernel_str(parent_name, sizeof(parent_name),
                                          BPF_CORE_READ(parent, d_name.name));

                if (name_equals(parent_name, bp->parent)) {
                    struct dentry *grandp = BPF_CORE_READ(parent, d_parent);
                    if (grandp) {
                        struct dentry *ggp = BPF_CORE_READ(grandp, d_parent);
                        if (ggp == grandp) {
                            // => /parent/child => 
                            return -EPERM;
                        }
                    }
                }
            }
        }

        current = BPF_CORE_READ(current, d_parent);
    }

    return 0;
}
