
/*! @file
 *  Pintool with a simple cache and row buffer simulator for counting reads, writes, cache hits and misses, among other memory related 
 *  operations. Note: the row buffer accesses are currently only made by reads in order to simulate a write-bypass optimization for NVMMs
 *  and all addresses who aren't on the stack are considered to be on the heap.
 */

#include "pin.H"
#include <iostream>
#include <fstream>

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Simulator structs and definitions
/* ================================================================== */

typedef unsigned long long address_64; // Represent a 64-bit memory address.

typedef struct simulator simulator;

#define READ 0
#define WRITE 1

/** Represents the cache lines inside the cache */
typedef struct cache_line {
    address_64 tag;             // Cache line tag.
    bool valid;                 // Valid bit.
    struct cache_line* next;    // Pointer to the next line in the set. Used for implementing the LRU eviction policy.
    bool* dirty;                // Pointer to an array of dirty bits corresponding to each byte in the line.
} cache_line;

/** Represents the cache and it's internal data */
typedef struct {
    simulator* parent_sim;      // Pointer to parent simulator.

    cache_line** sets;          // Pointer to array holding all cache sets.
    cache_line* lines;          // Pointer to the starting address of the allocated cache lines.
    // Needed for deallocation and counting later.

    /** Internal data */
    int no_sets;                // Number of sets in the cache.
    int no_lines;               // Number of cache lines.
    int size;                   // Size of the cache in bytes.
    int line_size;              // Size of the cache lines/blocks.
    int assoc;                  // The associativity of the cache. 1 = direct mapped.
    int tag_shift;              // How much you need to shift the address bits to get the tag.

    /** Statistics */
    long no_mem_writes;          // Increments when a cache line is written to memory.
    long no_bytes_written;       // Number of bytes that have been written to. Based on the number of dirty bits.
    long no_cache_straddles;     // Number of times a read or write straddles a cache line.
    long hits;                   // Number of cache hits.
    long misses;                 // Number of cache misses.
    long no_read_misses;         // Number of cache misses that are reads.
    long no_write_misses;        // Number of cache misses that are reads.
    long no_evicts;              // Number of times cache lines are evicted from the cache due to lack of room in set.
    long no_write_lookups;       // Number of times a write instruction looks for a tag in the cache.
    long no_read_lookups;        // Number of times a write instruction looks for a tag in the cache.
    long no_write_straddles;     // Number of times a write instruction straddles cache lines.
    long no_read_straddles;      // Number of times a read instruction straddles cache lines.
    long no_stack_misses;        // Number of times a read/write to a stack address misses.
    long no_heap_misses;         // Number of times a read/write to a heap address misses.
} cache;

/** Represents the row buffer and it's internal data */
typedef struct {
    address_64 row_page;        // Page number of page in row buffer.
    bool dirty_bit;             // Checks if row has been written to or not.
} row_buffer;

/** Simulator containing pointer to cache and row buffer */
typedef struct simulator {
    cache* cache_ptr;
    row_buffer* row_buffer_ptr;
    address_64 stack_ptr;
    int row_buffer_mode;
    int no_banks;
    int page_shift;             // Amount to shift an address to the get the page number for row buffers.

    /** Statistics */
    long no_stack_reads;
    long no_stack_writes;
    long no_heap_reads;
    long no_heap_writes;

    long no_row_buffer_accesses;    // Number of row buffer accesses.
    long row_read_hits;                 // Number of row buffer read hits.
    long row_write_hits;                // Number of row buffer write hits.
    long row_clean_read_misses;               // Number of row buffer clean read misses.
    long row_dirty_read_misses;               // Number of row buffer dirty read misses.
    long row_clean_write_misses;              // Number of row buffer clean write misses.
    long row_dirty_write_misses;              // Number of row buffer clean write misses.
    long no_dirty_evicts;           // Number of evictions of dirty row buffer pages.
} simulator;

/* ================================================================== */
// Initialization functions
/* ================================================================== */

/**
 * Calculates how much you need to shift the address in order to get address tag or page number.
 * @param size The size of the cache lines or the row buffer (a page).
 * @return The number of places to shift the address to get the tag or page number.
 */
int calc_shift(int size) {
    return log2((double) size);
}

/**
 * Checks if an integer is a power of two. Used for sanity checks when creating the cache.
 * @param num Integer to check
 * @return True if integer is a power of two else false.
 */
bool is_power_of_two(int num) {
    return ((((num)&(num-1)) == 0) && (num > 0));
}

/**
 * Initializes an empty cache line.
 * @param line Pointer to a cache line to initialize.
 * @param next Pointer to the next cache line in the set. Can be NULL if this is the last line in the set.
 * @param line_size The size of the cache line.
 */
void initialize_line(cache_line* line, cache_line* next, int line_size) {
    line->valid = false;
    line->tag = 0;
    line->next = next;
    line->dirty = (bool*) calloc(sizeof(bool), line_size);
}

/**
 * Set the allocated cache lines pointers to the other cache lines in its set. Also sets the pointers of the set array.
 * Also calls initialize_line function for each cache line. This function in as part of creating a new cache.
 * @param self Pointer to cache whose set pointers and cache line pointers need to be set.
 */
void init_cache_pointers(cache *self) {
    cache_line* current_line = self->lines;
    for(int i = 0; i < self->no_sets; i++) {
        self->sets[i] = current_line;
        for(int j = 0; j < self->assoc-1; j++, current_line++) {
            initialize_line(current_line, current_line + 1, self->line_size);
        }
        initialize_line(current_line++, NULL, self->line_size);
    }
}

/**
 * Creates a representation of a row buffer.
 * @param page_size The size of the row buffer (a page) in bytes.
 * @return A pointer to the the created row buffer.
 */
row_buffer* create_row_buffers(int no_banks) {
    row_buffer* self = (row_buffer*) calloc(no_banks, sizeof(row_buffer));
    return self;
}

/**
 * Creates a representation of a cache.
 * @param size The total size of the cache in bytes.
 * @param line_size The size of each cache line/block in bytes.
 * @param assoc The associativity of the cache.
 * @return A pointer to the created cache.
 */
cache* create_cache(simulator* parent, int size, int line_size, int assoc) {
    cache* self = (cache*) malloc(sizeof(cache));

    /** Set internal data */
    self->parent_sim = parent;
    self->size = size;
    self->line_size = line_size;
    self->assoc = assoc;
    self->no_sets = size/line_size/assoc;
    self->no_lines = size/line_size;
    self->tag_shift = calc_shift(line_size);

    /** Malloc and initialize sets and lines */
    cache_line** sets = (cache_line**) malloc(self->no_sets*sizeof(cache_line*));
    cache_line* lines = (cache_line*) malloc(self->no_lines*sizeof(cache_line));
    self->sets = sets;
    self->lines = lines;
    init_cache_pointers(self);

    return self;
}

/**
 * Creates a simulator representing a simplified memory system containing a cache and optionally a row buffer.
 * @param cache_size The total size of the cache in bytes.
 * @param line_size The size of each cache line/block in bytes.
 * @param assoc The associativity of the cache.
 * @param page_size Size of the row buffer.
 * @return A pointer to the created simulator.
 */
simulator* create_simulator(int cache_size, int line_size, int assoc, int row_buffer_size, int row_buffer_mode,
                            int no_chips, int no_banks) {
    simulator* self = (simulator*) malloc(sizeof(simulator));
    self->cache_ptr = create_cache(self, cache_size, line_size, assoc);
    self->row_buffer_mode = row_buffer_mode;
    self->no_banks = no_banks;
    if(row_buffer_mode > 0) {
        self->row_buffer_ptr = create_row_buffers(self->no_banks);
        self->page_shift = calc_shift(row_buffer_size*no_chips);
    }
    return self;
}

/* ================================================================== */
// Runtime functions
/* ================================================================== */

bool is_on_stack(simulator* self, address_64 addr) {
    return addr >= self->stack_ptr;
}

/**
 * Function that takes an address and translates it to a tag for the cache or a page number for the row buffer.
 * Tags in this simulator includes the index, this is usually not the case in the real world but has no impact in terms
 * of this simulator.
 * @param self Pointer to cache
 * @parm address Memory address to be translated
 * @return Translated address
 */
address_64 shift_address(int shift_amount, address_64 addr) {
    return addr >> shift_amount;
}

/**
 * Function that returns the cache index of a tag.
 * @param self Pointer to cache
 * @parm tag Memory tag to be translated
 * @return Cache index
 */
int get_index(cache* self, address_64 tag) {
    int index = tag & (self->no_sets-1);
    return index;
}

/**
 * Returns the offset inside a cache line for a certain memory address.
 * @param self Pointer to cache in which the offset is to be calculated.
 * @param addr The address whose offset it to be calculated.
 * @return Offset.
 */
int get_offset(cache* self, address_64 addr) {
    int mask = self->line_size-1;
    return addr & mask;
}

/**
 * Sums up the and returns the number of dirty bits withing a single cache line.
 * @param dirty_arr Pointer to a cache lines array of dirty bits.
 * @param line_size Cache line size.
 * @return Sum of dirty bits in the dirty bit array.
 */
int check_dirty(bool* dirty_arr, int line_size) {
    int sum = 0;
    for(int i= 0; i < line_size; i++) {
        if(dirty_arr[i] == true) {
            sum++;
        }
    }
    return sum;
}

/**
 * Accesses the row buffer and checks if the cache line is present in the row buffer, if not loads data (usually a page)
 * where the line is present.
 * @param self Pointer to the row buffer.
 * @param addr Address inside the cache line to be loaded.
 */
void access_row_buffers(simulator *self, address_64 addr, int ins_type) {
    self->no_row_buffer_accesses++;
    address_64 page_number = shift_address(self->page_shift, addr);
    int bank_no = page_number % self->no_banks;
    if(page_number == self->row_buffer_ptr[bank_no].row_page) {
        if(ins_type == READ) {
            self->row_read_hits++;
        } else {
            self->row_buffer_ptr[bank_no].dirty_bit = true;
            self->row_write_hits++;
        }
    } else {
        if(self->row_buffer_ptr[bank_no].dirty_bit == true) {
            self->no_dirty_evicts++;
        }
        self->row_buffer_ptr[bank_no].row_page = page_number;
        if (ins_type == READ) {
            if(self->row_buffer_ptr[bank_no].dirty_bit == true) {
                self->row_dirty_read_misses++;
                self->row_buffer_ptr[bank_no].dirty_bit = false;
            } else {
                self->row_clean_read_misses++;
            }

        } else {
            if(self->row_buffer_ptr[bank_no].dirty_bit == true) {
                self->row_dirty_write_misses++;
            } else {
                self->row_clean_write_misses++;
                self->row_buffer_ptr[bank_no].dirty_bit = true;
            }

        }
    }
}

/**
 * Adds a cache line to the cache. Also handles evictions of cache lines according to the LRU eviction policy.
 * @param self Pointer to cache.
 * @param tag Tag of cache line to be added.
 * @param index Index of cache line to be added.
 */
void add_to_cache(cache* self, address_64 tag, address_64 index) {
    // Set line to the last line in the set and prev_line to the second last.
    cache_line* line = self->sets[index];
    cache_line* prev_line = NULL;
    for (int i = 0; i < self->assoc - 1; i++) {
        prev_line = line;
        line = line->next;
    }

    // If valid cache line is evicted, check number of dirty bits of evicted cache line if valid and update statistics.
    if (line->valid == true) {
        int bytes_to_write = check_dirty(line->dirty, self->line_size);
        if (bytes_to_write > 0) {
            self->no_bytes_written = self->no_bytes_written + bytes_to_write;
            self->no_mem_writes++;
        }
        self->no_evicts++;
    }

    // Update cache line
    line->valid = true;
    line->tag = tag;
    for (int i = 0; i < self->line_size; i++) {
        line->dirty[i] = false;
    }
    // If associativity is greater than 1 (indicated by prev_line = NULL), set line to first line in set.
    if(prev_line != NULL) {
        line->next = self->sets[index];
        self->sets[index] = line;
        // Make new last's next pointer be NULL.
        prev_line->next = NULL;
    }
}

/**
 * Records write to a cache line by updating its dirty bit array.
 * @param self Pointer to cache.
 * @param addr Address to be written to.
 * @param line Cache line to be written to.
 * @param write_size Size of the write.
 */
void write_to_line(cache* self, address_64 addr, cache_line* line, int write_size) {
    int offset = get_offset(self, addr);
    for (int i = offset; i < (offset + write_size); i++) {
        line->dirty[i] = true;
    }
}

/**
 * Move a cache line first in a set. Used for keeping track of which order cache lines have been used for the LRU
 * eviction policy.
 * @param self Pointer to cache.
 * @param line Pointer to cache line to be moved.
 * @param prev_line Pointer to cache line directly before line to be moved.
 * @param index Index to the set which the cache line belongs to.
 */
void move_line_first(cache* self, cache_line* line, cache_line* prev_line, int index) {
    // If prev_line = NULL that indicates that line already is first
    if(prev_line == NULL) {
        return;
    }
    prev_line->next = line->next;
    line->next =self->sets[index];
    self->sets[index] = line;
}

/**
 * Function that checks if address is present in cache and if valid bit is set. If not present or invalid calls the
 * add_to_cache function. Also includes functionality for checking if an instruction straddles cache lines in which case
 * it makes a lookup for that cache line too.
 * @param self Pointer to cache.
 * @param addr Address to be check if present in cache.
 * @param ins_type Type of instruction. READ or WRITE.
 * @param ins_size Size of the read or write in bytes.
 */
void cache_lookup(cache *self, address_64 addr, int ins_type, int ins_size) {
    bool on_stack = is_on_stack(self->parent_sim, addr);

    // Update internal statistics.
    if(ins_type == WRITE) {
        self->no_write_lookups++;
        // Check if address is on heap or stack.
        if(on_stack) {
            self->parent_sim->no_stack_writes++;
        } else {
            self->parent_sim->no_heap_writes++;
        }
    } else {
        self->no_read_lookups++;
        if(on_stack) {
            self->parent_sim->no_stack_reads++;
        } else {
            self->parent_sim->no_heap_reads++;
        }
    }

    address_64 tag = shift_address(self->tag_shift, addr);
    int index = get_index(self, tag);
    bool straddle = false;

    // Check if instruction straddles cache lines
    address_64 next_addr;
    int remaining_size;
    int offset = get_offset(self, addr);
    if(offset + ins_size > self->line_size) {
        straddle = true;
        self->no_cache_straddles++;
        if(ins_type == WRITE) {
            self->no_write_straddles++;
        } else {
            self->no_read_straddles++;
        }
        next_addr = addr + (self->line_size - offset); // Starting address of instruction on next cache line.
        remaining_size = ins_size - (self->line_size - offset); // Size of read or write to be done on next line
        ins_size = self->line_size - offset; // Size of read or write to be done on this line.
    }


    // Goes through set to see if line with the correct tag is present at correct index.
    cache_line* line = self->sets[index];
    cache_line* prev_line = NULL;
    bool is_hit = false;
    while(line != NULL) {
        if (line->tag == tag) {
            is_hit = true;
            break;
        } else {
            prev_line = line;
            line = line->next;
        }
    }

    if(is_hit) {
        // CACHE HIT.
        move_line_first(self, line, prev_line, index); // Move line first, as part of LRU policy.
        if(ins_type == WRITE){
            write_to_line(self, addr, line, ins_size);
        }
        self->hits++; // Record cache hit.
    } else {
        // CACHE MISS.
        self->misses++; //Record miss.

        //Depending row buffer mode make a row buffer call here.
        if(self->parent_sim->row_buffer_mode == 1 || (self->parent_sim->row_buffer_mode == 2 && ins_type == READ)) {
            access_row_buffers(self->parent_sim, addr, ins_type);
        }

        // Add cache line with current tag to cache.
        add_to_cache(self, tag, index);

        // If instruction is a read and simulator uses row buffer, check row buffer to see if cache line is present.
        if(ins_type == READ) {
            self->no_read_misses++;
        }


        // Update dirty bits if instruction is a write.
        if (ins_type == WRITE) {
            self->no_write_misses++;
            write_to_line(self, addr, self->sets[index], ins_size);
        }

        // Record stack and heap misses.
        if(on_stack) {
            self->no_stack_misses++;
        } else {
            self->no_heap_misses++;
        }
    }

    if(straddle) {
        // If instruction straddles cache line perform lookup on remaining instruction.
        cache_lookup(self, next_addr, ins_type, remaining_size);
    }
}

/**
 * Counts how many cache lines currently in the cache that has been written to and how many written bytes that is,
 * and updates internal statistics accordingly.
 * @param self Pointer to cache.
 */
void count_dirty_bits(cache* self) {
    cache_line* line = self->lines;
    int sum = 0;
    bool line_written;
    for(int i = 0; i < self->no_lines; i++) {
        line_written = false;
        for(int j = 0; j < self->line_size; j++) {
            if(line->dirty[j] == true) {
                line_written = true;
                sum++;
            }
        }
        if(line_written) {
            self->no_mem_writes++;
        }
        line = line + 1;
    }
    self->no_bytes_written = self->no_bytes_written + sum;
}

/* ================================================================== */
// Simulator teardown functions
/* ================================================================== */

/**
 * Frees all memory allocated to the cache.
 * @param self Pointer to cache.
 */
void delete_cache(cache* self) {
    cache_line* line = self->lines;
    for(int i = 0; i < self->no_lines; i++) {
        free(line->dirty);
        line = line + 1;
    }
    free(self->lines);
    free(self->sets);
    free(self);
}

/**
 * Frees all memory allocated to the simulator.
 * @param self Pointer to simulator
 */
void delete_simulator(simulator* self) {
    delete_cache(self->cache_ptr);
    free(self->row_buffer_ptr);
    free(self);
}

/* ================================================================== */
// Utility test functions
/* ================================================================== */

/**
 * Prints hits and misses in the cache. Only for testing purposes.
 * @param self Pointer to simulator.
 */
void print_hit_miss_cache(simulator* self) {
    printf("Hits: %ld\nMisses: %ld\n", self->cache_ptr->hits, self->cache_ptr->misses);
}

/**
 * Prints hits and misses in the cache. Only for testing purposes.
 * @param self Pointer to simulator.
 */
void print_hit_miss_row(simulator *self) {
    printf("Row read hits: %ld\nRow read clean misses: %ld\nRow read dirty misses: %ld\n"
           "Row write hits: %ld\nRow write clean misses: %ld\nRow write dirty misses: %ld\n", self->row_read_hits,
           self->row_clean_read_misses, self->row_dirty_read_misses, self->row_write_hits, self->row_clean_write_misses,
           self->row_dirty_write_misses);
}

/* ================================================================== */
// Global variables 
/* ================================================================== */

simulator* mySim;

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 readCount = 0;       //total number of memory reads
UINT64 writeCount = 0;       //total number of memory writes

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for PinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<UINT32> KnobAssociativty(KNOB_MODE_WRITEONCE, "pintool", 
    "a", "2", "Set associativity of cache. 1 represents a direct-mapped cache");

KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE, "pintool", 
    "l", "64", "Set cache line size in bytes.");   

KNOB<UINT32> KnobSize(KNOB_MODE_WRITEONCE, "pintool", 
    "s", "8388608", "Set cache size in bytes.");

KNOB<UINT32> KnobRowSize(KNOB_MODE_WRITEONCE, "pintool", 
    "r", "4096", "Set row buffer size in bytes.");

KNOB<UINT32> KnobRowMode(KNOB_MODE_WRITEONCE, "pintool", 
    "m", "1", "Set row buffer mode. 0 = no row buffer. 1 = row buffer handles both reads" 
    " and writes. 2 = writes bypass the row buffers");

KNOB<UINT32> KnobChipNum(KNOB_MODE_WRITEONCE, "pintool", 
    "c", "8", "Set the number of memory chips");

KNOB<UINT32> KnobBankNum(KNOB_MODE_WRITEONCE, "pintool", 
    "b", "8", "Set the number of banks per memory chip");            

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool simulates a cache and a an optional row buffer, and prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and reads and writes, cache and row buffer hits and misses (and more) in the run " << endl <<
            "application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/*!
 * Increase counter of the executed memory reads and runs the instruction through the simulators.
 * This function is called for every memory read when it is about to be executed.
 * @param[in]   ctxt  read-only CPU context.
 * @param[in]   addr  address of the data to be read.
 * @param[in]   size  size of the write.
 */
VOID AnalyseMemRead(const CONTEXT *ctxt, VOID * addr, UINT32 size)
{
    ADDRINT stackPointer = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    mySim->stack_ptr = (address_64) stackPointer;

    readCount++; // Increase counter for number of read instructions.

    // Run the instruction through the cache simulator (and optionally the row buffer simulator).
    cache_lookup(mySim->cache_ptr, (address_64) addr, READ, (int) size);
}

/*!
 * Increase counter of the executed memory writes and runs the instruction through the simulators.
 * This function is called for every memory write when it is about to be executed.
 * @param[in]   ctxt  read-only CPU context.
 * @param[in]   addr  address of the data to be written.
 * @param[in]   size  size of the write.
 */
VOID AnalyseMemWrite(const CONTEXT *ctxt, VOID * addr, UINT32 size)
{
    ADDRINT stackPointer = PIN_GetContextReg(ctxt, REG_STACK_PTR);
    mySim->stack_ptr = (address_64) stackPointer;

    writeCount++; // Increase counter for number of read instructions.

    // Run the instruction through the cache simulator (and optionally the row buffer simulator).
    cache_lookup(mySim->cache_ptr, (address_64) addr, WRITE, (int) size); 
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


/*!
 * This function is called every time a new instuction is encountered.
 * @param[in]   ins             instruction to instrument
 * @param[in]   v               value specified by the tool in the 
 *                              INS_AddInstrumentFunction function call
 */
VOID Instruction(INS ins, VOID *v) 
{
    if(INS_IsMemoryRead(ins))
    {
        // To make the Pintool portable across platforms. Use INS_InsertPredicatedCall instead of INS_InsertCall to avoid 
        // generating references to instructions that are predicated and the predicate is false (predication is only relevant 
        // for IA-64 ISA).        
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) AnalyseMemRead, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    else if(INS_IsMemoryWrite(ins))
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) AnalyseMemWrite, IARG_CONST_CONTEXT, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }

}

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    count_dirty_bits(mySim->cache_ptr);

    *out <<  "===============================================" << endl;
    *out <<  "PinTool analysis results: " << endl << endl;

    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of read instructions: " << readCount  << endl;
    *out <<  "Number of write instructions: " << writeCount  << endl << endl;

    *out <<  "Number of cache read lookups: " << mySim->cache_ptr->no_read_lookups << endl;
    *out <<  "Number of cache write lookups: " << mySim->cache_ptr->no_write_lookups << endl;
    *out <<  "Number of cache hits: " << mySim->cache_ptr->hits << endl;
    *out <<  "Number of cache misses: " << mySim->cache_ptr->misses << endl << endl;

    *out <<  "Number of cache read misses: " << mySim->cache_ptr->no_read_misses << endl;
    *out <<  "Number of cache write misses: " << mySim->cache_ptr->no_write_misses << endl << endl;

    *out <<  "Number of cache misses for stack addresses: " << mySim->cache_ptr->no_stack_misses << endl; 
    *out <<  "Number of cache misses for heap addresses: " << mySim->cache_ptr->no_heap_misses << endl << endl;

    *out <<  "Number of cache line straddles: " << mySim->cache_ptr->no_cache_straddles << endl;
    *out <<  "Number of read cache line straddles: " << mySim->cache_ptr->no_read_straddles << endl;
    *out <<  "Number of write cache line straddles: " << mySim->cache_ptr->no_write_straddles << endl << endl;

    *out <<  "Number of reads to stack: " << mySim->no_stack_reads << endl;
    *out <<  "Number of writes to stack: " << mySim->no_stack_writes << endl;
    *out <<  "Number of reads to heap: " << mySim->no_heap_reads << endl;
    *out <<  "Number of writes to heap: " << mySim->no_heap_writes << endl << endl;

    *out <<  "Number of bytes written to memory: " << mySim->cache_ptr->no_bytes_written << endl;
    *out <<  "Number of writes to memory: " << mySim->cache_ptr->no_mem_writes << endl;
    *out <<  "Number of cache line evictions: " <<  mySim->cache_ptr->no_evicts << endl << endl;

    if(KnobRowMode > 0) 
    {
        *out <<  "Number of row buffer read hits: " << mySim->row_read_hits << endl;
        *out <<  "Number of row buffer clean read misses: " << mySim->row_clean_read_misses << endl;
        *out <<  "Number of row buffer dirty read misses: " << mySim->row_dirty_read_misses << endl;
        *out <<  "Number of row buffer write hits: " << mySim->row_write_hits << endl;
        *out <<  "Number of row buffer clean write misses: " << mySim->row_clean_write_misses << endl;
        *out <<  "Number of row buffer dirty write misses: " << mySim->row_dirty_write_misses << endl;
        *out <<  "Number of evictions of dirty row buffer pages: " << mySim->no_dirty_evicts << endl << endl;        
    }

    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "===============================================" << endl;

    delete_simulator(mySim);
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str(), std::ios::app);}

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);

        // Register function to be called to instrument instructions.
        INS_AddInstrumentFunction(Instruction, 0);
    }

    // Sanity check for cache parameters
    if (!is_power_of_two(KnobSize/KnobLineSize/KnobAssociativty) || !is_power_of_two(KnobLineSize) || 
        !is_power_of_two(KnobRowSize) || !(KnobRowSize > KnobLineSize))
    {
        cerr << "Error: chache line size and the number of sets in the cache each need" 
             << " to be a power of two." << endl;
        return 1;
    }

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;
    
    // Initializes simulatior
    mySim = create_simulator(KnobSize, KnobLineSize, KnobAssociativty, KnobRowSize, KnobRowMode, KnobChipNum, KnobBankNum);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
