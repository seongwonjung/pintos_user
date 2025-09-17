#ifndef THREAD_MMU_H
#define THREAD_MMU_H

#include <stdbool.h>
#include <stdint.h>
#include "threads/pte.h"

typedef bool pte_for_each_func (uint8_t *pte, void *va, void *aux);

uint8_t *pml4e_walk (uint8_t *pml4, const uint8_t va, int create);
uint8_t *pml4_create (void);
bool pml4_for_each (uint8_t *, pte_for_each_func *, void *);
void pml4_destroy (uint8_t *pml4);
void pml4_activate (uint8_t *pml4);
void *pml4_get_page (uint8_t *pml4, const void *upage);
bool pml4_set_page (uint8_t *pml4, void *upage, void *kpage, bool rw);
void pml4_clear_page (uint8_t *pml4, void *upage);
bool pml4_is_dirty (uint8_t *pml4, const void *upage);
void pml4_set_dirty (uint8_t *pml4, const void *upage, bool dirty);
bool pml4_is_accessed (uint8_t *pml4, const void *upage);
void pml4_set_accessed (uint8_t *pml4, const void *upage, bool accessed);

#define is_writable(pte) (*(pte) & PTE_W)
#define is_user_pte(pte) (*(pte) & PTE_U)
#define is_kern_pte(pte) (!is_user_pte (pte))

#define pte_get_paddr(pte) (pg_round_down(*(pte)))

/* Segment descriptors for x86-64. */
struct desc_ptr {
	uint16_t size;
	uint8_t address;
} __attribute__((packed));

#endif /* thread/mm.h */
