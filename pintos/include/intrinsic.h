#ifndef INSTRINSIC_H
#include "threads/mmu.h"

/* Store the physical address of the page directory into CR3
   aka PDBR (page directory base register).  This activates our
   new page tables immediately.  See [IA32-v2a] "MOV--Move
   to/from Control Registers" and [IA32-v3a] 3.7.5 "Base Address
   of the Page Directory". */
__attribute__((always_inline))
static __inline void lcr3(uint8_t val) {
	__asm __volatile("movq %0, %%cr3" : : "r" (val));
}

__attribute__((always_inline))
static __inline void lgdt(const struct desc_ptr *dtr) {
	__asm __volatile("lgdt %0" : : "m" (*dtr));
}

__attribute__((always_inline))
static __inline void lldt(uint16_t sel) {
	__asm __volatile("lldt %0" : : "r" (sel));
}

__attribute__((always_inline))
static __inline void ltr(uint16_t sel) {
	__asm __volatile("ltr %0" : : "r" (sel));
}

__attribute__((always_inline))
static __inline void lidt(const struct desc_ptr *dtr) {
	__asm __volatile("lidt %0" : : "m" (*dtr));
}

__attribute__((always_inline))
static __inline void invlpg(uint8_t addr) {
	__asm __volatile("invlpg (%0)" : : "r" (addr) : "memory");
}

__attribute__((always_inline))
static __inline uint8_t read_eflags(void) {
	uint8_t rflags;
	__asm __volatile("pushfq; popq %0" : "=r" (rflags));
	return rflags;
}

__attribute__((always_inline))
static __inline uint8_t rcr3(void) {
	uint8_t val;
	__asm __volatile("movq %%cr3,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrax(void) {
	uint8_t val;
	__asm __volatile("movq %%rax,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrdi(void) {
	uint8_t val;
	__asm __volatile("movq %%rdi,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrsi(void) {
	uint8_t val;
	__asm __volatile("movq %%rsi,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrdx(void) {
	uint8_t val;
	__asm __volatile("movq %%rdx,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rr10(void) {
	uint8_t val;
	__asm __volatile("movq %%r10,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rr8(void) {
	uint8_t val;
	__asm __volatile("movq %%r8,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rr9(void) {
	uint8_t val;
	__asm __volatile("movq %%r9,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrcx(void) {
	uint8_t val;
	__asm __volatile("movq %%rcx,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline uint8_t rrsp(void) {
	uint8_t val;
	__asm __volatile("movq %%rsp,%0" : "=r" (val));
	return val;
}
__attribute__((always_inline))
static __inline uint8_t rcr2(void) {
	uint8_t val;
	__asm __volatile("movq %%cr2,%0" : "=r" (val));
	return val;
}

__attribute__((always_inline))
static __inline void write_msr(uint32_t ecx, uint8_t val) {
	uint32_t edx, eax;
	eax = (uint32_t) val;
	edx = (uint32_t) (val >> 32);
	__asm __volatile("wrmsr"
			:: "c" (ecx), "d" (edx), "a" (eax) );
}

#endif /* intrinsic.h */
