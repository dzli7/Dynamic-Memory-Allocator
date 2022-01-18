/*
 * mm-implicit.c - The best malloc package EVAR!
 *
 * TODO (bug): mm_realloc and mm_calloc don't seem to be working...
 * TODO (bug): The allocator doesn't re-use space very well...
 */

#include <stdint.h>

#include "memlib.h"
#include "mm.h"
#include "string.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

typedef struct {
    size_t size;
    block_t *next;
    block_t *prev;
} node_t;

typedef struct {
    size_t size;
} footer_t;

static node_t *free_list = NULL;
/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

void remove_block(node_t *node) {
    if (node == NULL) {
        return;
    }
    node_t *prev_node = (node_t *) node->prev;
    node_t *next_node = (node_t *) node->next;
    if (prev_node != NULL) {
        prev_node->next = (block_t *) next_node;
    }
    else if (prev_node == NULL) {
        free_list = next_node;
    }
    if (next_node != NULL) {
        next_node->prev = (block_t *) prev_node;
    }
    else if (next_node == NULL) {
        prev_node->next = NULL;
    }
}

void add_block(node_t *node) {
    if (node != NULL) {
        node_t *old_free_list = free_list;
        free_list = node;
        free_list->next = NULL;
        free_list->prev = (block_t *) old_free_list;
        old_free_list->next = (block_t *) free_list;
        free_list = old_free_list;
    }
    else {
        free_list = node;
        free_list->next = NULL;
        free_list->prev = NULL;
    }
}

size_t min_size(size_t a, size_t b) {
    if (a <= b) {
        return a;
    }
    return b;
}

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    footer_t *footer = (void *) block + size - sizeof(footer_t);
    footer->size = size;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/**
 * Finds the first free node in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the implicit list
    for (node_t *curr = free_list; curr->next != NULL; curr = (node_t *) curr->next) {
        // If the block is free and large enough for the allocation, return it
        if (get_size((block_t *) curr) >= size - sizeof(footer_t)) {
            return ((block_t *) curr);
        }
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    free_list = NULL;
    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header/footer and be 16-byte aligned
    size = round_up(sizeof(block_t) + sizeof(footer_t) + size, ALIGNMENT);

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        remove_block((node_t *) block);
        // block_t *next_block = (void *) block + size;
        // if (get_size(block) > sizeof(block_t) + sizeof(footer_t) + size) {
        //     if (block == mm_heap_last) {
        //         mm_heap_last = next_block;
        //     }
        //     set_header(next_block, get_size(block) - size, false);
        //     add_block((node_t *) next_block);
        // }
        // size = min_size(get_size(block), size);
        set_header(block, size, true);
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header(block, size, true);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    add_block((node_t *) block);
    block_t *prev_block = NULL;
    block_t *next_block = NULL;
    if (block != mm_heap_first) {
        footer_t *last_footer = (void *) block - sizeof(footer_t);
        prev_block = (void *) block - last_footer->size;
    }
    if (block != mm_heap_last) {
        next_block = (void *) block + get_size(block);
    }
    set_header(block, get_size(block), false);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        void *new_block = mm_malloc(size);
        return new_block;
    }
    else if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    void *new_ptr = mm_malloc(size);
    block_t *old_ptr_block = block_from_payload(old_ptr);
    block_t *new_ptr_block = block_from_payload(new_ptr);

    size_t old_ptr_size = get_size(old_ptr_block);
    size_t new_block_size = get_size(new_ptr_block);

    size_t min = min_size(old_ptr_size, new_block_size) - sizeof(size_t);
    memcpy(new_ptr, old_ptr, min);
    mm_free(old_ptr);
    return new_ptr;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0) {
        return NULL;
    }
    size_t new_size = nmemb * size;
    void *ptr = mm_malloc(new_size);
    block_t *block = block_from_payload(ptr);
    memset(block, 0, new_size);
    return block;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
}