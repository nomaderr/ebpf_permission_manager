# eBPF Permission Manager

## Overview

`ebpf_permission_manager` is a security tool that uses **eBPF (Extended Berkeley Packet Filter)** to control file system permissions at the kernel level. It enforces restrictions on file creation in specific directories by leveraging **LSM hooks** inside an eBPF program. 

The project consists of:
- **eBPF Program (C)**: Implements logic for restricting file creation based on a **BPF hash map**.
- **User-Space Controller (Go)**: Manages eBPF program lifecycle, updates the permission rules, and interacts with **bpftool**.

## Features

✅ Restricts file creation in specific directories  
✅ Uses **eBPF maps** for dynamic rule updates  
✅ Implements **LSM hooks** (`inode_create`) for access control  
✅ Supports **hot updates** without restarting the eBPF program  
✅ Lightweight and fast, running entirely in **kernel space**  

---

## Architecture

### 1️⃣ **eBPF Program (C)**

The eBPF program operates at the kernel level, leveraging an **LSM (Linux Security Module) hook** to intercept file creation attempts. 

- It **stores blocked directory paths** in an **eBPF hash map**.
- Uses **BPF core helpers** to inspect file paths during `inode_create`.
- If a match is found, the file creation is **denied (EPERM)**.
- Logs violations to **trace_pipe** for auditing.

#### **eBPF Map Structure**
- **Type:** `BPF_MAP_TYPE_HASH`
- **Key:** `u32` (always `0` since we store a single rule)
- **Value:** `struct blocked_path_t` (parent + child directory)

---

### 2️⃣ **User-Space Controller (Go)**

The **Go-based user-space manager** is responsible for:
- **Compiling and loading** the eBPF program (`ecc`, `ecli`)
- **Finding and pinning the BPF map** (`bpftool map pin`)
- **Updating access control rules dynamically** (`bpftool map update`)
- **Logging denied access attempts**  
- **Ensuring compatibility across kernel versions**

---

## Installation

### **Requirements**
- **Linux Kernel ≥ 5.8** (eBPF LSM required)
- **bpftool** (`apt install bpftool` or `yum install bpftool`)
- **eBPF Compiler Collection (ECC, ECLI)**
- **Go ≥ 1.18** for user-space controller

### **Build & Run**

1️⃣ **Clone the repository**
```bash
git clone https://github.com/yourusername/ebpf_permission_manager.git
cd ebpf_permission_manager
