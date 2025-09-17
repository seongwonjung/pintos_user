#ifndef THREADS_LOADER_H
#define THREADS_LOADER_H

/* Constants fixed by the PC BIOS. */
#define LOADER_BASE 0x7c00      /* Physical address of loader's base. */
#define LOADER_END  0x7e00      /* Physical address of end of loader. */

/* Physical address of kernel base. */
#define LOADER_KERN_BASE 0x8004000000

/* Kernel virtual address at which all physical memory is mapped. */
#define LOADER_PHYS_BASE 0x200000

/* Multiboot infos */
#define MULTIBOOT_INFO       0x7000
#define MULTIBOOT_FLAG       MULTIBOOT_INFO
#define MULTIBOOT_MMAP_LEN   MULTIBOOT_INFO + 44
#define MULTIBOOT_MMAP_ADDR  MULTIBOOT_INFO + 48

#define E820_MAP MULTIBOOT_INFO + 52
#define E820_MAP4 MULTIBOOT_INFO + 56

/* Important loader physical addresses. */
#define LOADER_SIG (LOADER_END - LOADER_SIG_LEN)   /* 0xaa55 BIOS signature. */
#define LOADER_ARGS (LOADER_SIG - LOADER_ARGS_LEN)     /* Command-line args. */
#define LOADER_ARG_CNT (LOADER_ARGS - LOADER_ARG_CNT_LEN) /* Number of args. */

/* Sizes of loader data structures. */
#define LOADER_SIG_LEN 2
#define LOADER_ARGS_LEN 128
#define LOADER_ARG_CNT_LEN 4

/* 로더(loader)에 의해 정의된 GDT 셀렉터들.  
   더 많은 셀렉터들은 userprog/gdt.h에서 정의된다. */
#define SEL_NULL        0x00    /* Null selector.              → 널(null) 셀렉터 */
#define SEL_KCSEG       0x08    /* Kernel code selector.        → 커널 코드 셀렉터 */
#define SEL_KDSEG       0x10    /* Kernel data selector.        → 커널 데이터 셀렉터 */
#define SEL_UDSEG       0x1B    /* User data selector.          → 사용자 데이터 셀렉터 */
#define SEL_UCSEG       0x23    /* User code selector.          → 사용자 코드 셀렉터 */
#define SEL_TSS         0x28    /* Task-state segment.          → 태스크 상태 세그먼트 */
#define SEL_CNT         8       /* Number of segments.          → 세그먼트 개수 */

#endif /* threads/loader.h */
