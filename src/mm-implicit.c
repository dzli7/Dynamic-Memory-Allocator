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

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

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
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

void coalesce() {
    for (block_t *block = mm_heap_first; mm_heap_last != NULL && block <= mm_heap_last;
         block = (void *) block + get_size(block)) {
        if (!is_allocated(block)) {
            block_t *curr_block = block;
            size_t coalesce_size = get_size(block);
            for (block = ((void *) block) + get_size(block);
                 !is_allocated(block) && block <= mm_heap_last;
                 block = (void *) block + get_size(block)) {
                coalesce_size += get_size(block);
            }
            set_header(curr_block, coalesce_size, false);
        }
    }
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the implicit list
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        // If the block is free and large enough for the allocation, return it
        if (!is_allocated(curr) && get_size(curr) >= size) {
            return curr;
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
    size = round_up(sizeof(block_t) + size, ALIGNMENT);

    coalesce();

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        if (get_size(block) > sizeof(block_t) + size) {
            block_t *new_block = ((void *) block) + size;
            set_header(new_block, get_size(block) - size, false);
        }
        size = min_size(get_size(block), size);
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
