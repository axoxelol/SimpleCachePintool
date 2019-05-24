
/*! @file
 *  Pintool with a simple cache simulator for counting reads, writes, cache hits and misses, among other memory related 
 *  operations.
 */

#include "pin.H"
#include <iostream>
#include <fstream>


/* ================================================================== */
// Cache represenatation
/* ================================================================== */
typedef unsigned long long address_64; // Represent a 64-bit address.



#define READ 0
#define WRITE 1


/** Represents the cache lines inside the cache */
typedef struct cache_line {
    address_64 tag;             // Cache line tag.
    bool valid;                 // Valid bit.
    struct cache_line* next;    // Pointer to the next line in the set. Used for implementing the LRU eviction policy.
    int* dirty;                 // Pointer to an array of dirty bits corresponding to each byte in the line.
} cache_line;

/** Represents the cache and it's internal data */
typedef struct {
    cache_line** sets;          // Pointer to array holding all cache sets.
    cache_line* lines;          // Pointer to the starting address of the allocated cache lines.
    // Needed for deallocation and counting later.

    /** Internal data */
    int no_sets;                // Number of sets in the cache.
    int no_lines;               // Number of cache lines.
    int size;                   // Size of the cache in bytes.
    int line_size;             // Size of the cache lines/blocks.
    int assoc;                  // The associativity of the cache. 1 = direct mapped.
    int tag_shift;              // How much you need to shift the address bits to get the tag.

    /** Statistics */
    int no_mem_writes;          // Increments when a cache line is written to memory.
    int no_bytes_written;       // Number of bytes that have been written to. Based on the number of dirty bits.
    int no_cache_straddles;     // Number of times a read or write straddles a cache line.
    int misses;                 // Number of cache misses.
    int hits;                   // Number of cache hits.
    int no_evicts;              // Number of times cache lines are evicted from the cache due to lack of room in set.
    int no_write_lookups;       // Number of times a write instruction looks for a tag in the cache.
    int no_read_lookups;        // Number of times a write instruction looks for a tag in the cache.
    int no_write_straddles;      // Number of times a write instruction straddles cache lines.
    int no_read_straddles;       // Number of times a read instruction straddles cache lines.

} cache;

void cache_lookup(cache *self, address_64 addr, int ins_type, int ins_size);

/**
 * Calculates how much you need to shift the address in order to get address tag.
 * @param line_size The size of the cache lines
 * @return The number of places to shift the address to get the tag.
 */
int calc_shift(int line_size) {
    return log((double) line_size)/log((double)2);
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
    line->dirty = (int*) calloc(sizeof(int), line_size);
}


/**
 * Set the allocated cache lines pointers to the other cache lines in its set. Also sets the pointers of the set array.
 * Also calls initalize_line function for each cache line. This function in as part of creating a new cache.
 * @param self Pointer to cache whose set pointers and cache line pointers need to be set.
 */
void init_cache_pointers(cache *self) {
    cache_line* current_line = self->lines;


    for(int i = 0; i < self->no_sets; i++) {            // Loops through each set
        for(int j = 0; j < self->assoc; j++) {          // Loops through the entire line for each set.

            if (j == 0) {            // If first line in set, set pointer in set to this line.
                if(self->assoc == 1) {
                    initialize_line(current_line, NULL, self->line_size);
                } else {
                    initialize_line(current_line, current_line + 1, self->line_size);
                }
                self->sets[i] = current_line;
                current_line = current_line + 1;
            } else if(j == self->assoc-1) {             // if last line in set, set next pointer to NULL.
                initialize_line(current_line, NULL, self->line_size);
                current_line = current_line + 1;
            } else {
                initialize_line(current_line, current_line+1, self->line_size);
                current_line = current_line + 1;

            }
        }
    }
}
/**
 * Creates a representation of a cache.
 * @param size The total size of the cache in bytes.
 * @param line_size The size of each cache line/block.
 * @param assoc The associativity of the cache.
 * @return A pointer to the created cache.
 */
cache* create_cache(int size, int line_size, int assoc) {
    cache* self = (cache*) malloc(sizeof(cache));

    /** Set internal data */
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
 * Function that takes an address and translates it to a tag.
 * @param self Pointer to cache
 * @parm address Memory address to be translated
 * @return Translated address
 */
address_64 get_tag(cache* self, address_64 address) {
    return address >> self->tag_shift;
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
 * @param self Pointer to cache in wich the offset is to be calculated.
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
int check_dirty(int* dirty_arr, int line_size) {
    int sum = 0;
    for(int i= 0; i < line_size; i++) {
        if(dirty_arr[i] == 1) {
            sum++;
        }
    }
    return sum;
}

/**
 * Adds a cache line to the cache. Also handles evictions of cache lines.
 * @param self Pointer to cache.
 * @param tag Tag of cache line to be added.
 * @param index Index of cache line to be added.
 */
void add_to_cache(cache* self, address_64 tag, address_64 index) {
    cache_line* line = self->sets[index];
    // If direct mapped cache, evict data if valid and write to that cache line.
    if(self->assoc == 1) {
        if(line->valid == true) {
            int bytes_to_write = check_dirty(line->dirty, self->line_size);
            if (bytes_to_write > 0) {
                self->no_bytes_written = self->no_bytes_written + bytes_to_write;
                self->no_mem_writes++;
                self->no_evicts++;
            }
        }
        line->valid = true;
        line->tag = tag;
        for(int i = 0; i < self->line_size; i++) {
            line->dirty[i] = false;
        }
    } else {
        // If cache is set associative take the last line and make it first in the set as a way of representing the
        // LRU policy, by modifying pointers withing the set.
        cache_line* prev_line = NULL;

        // Set line to the last line in the set and prev_line to the second last.
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
                self->no_evicts++;
            }
        }

        // Update cache line
        line->next = self->sets[index];
        line->valid = true;
        line->tag = tag;
        for (int i = 0; i < self->line_size; i++) {
            line->dirty[i] = false;
        }
        // Set to first line in set
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
 * Function that checks if address is present in cache and if valid bit is set. If not present or invalid calls the
 * add_to_cache function. Also includes functionality for checking if an instruction straddles cache lines in which case
 * it makes a lookup for that cache line too.
 * @param self Pointer to cache.
 * @param addr Address to be check if present in cache.
 * @param ins_type Type of instruction. READ or WRITE.
 * @param ins_size Size of the read or write in bytes.
 */
void cache_lookup(cache *self, address_64 addr, int ins_type, int ins_size) {
    // Update internal statistics.
    if(ins_type == WRITE) {
        self->no_write_lookups++;
    } else {
        self->no_read_lookups++;
    }

    address_64 tag = get_tag(self, addr);
    int index = get_index(self, tag);
    bool straddle = false;

    // Check if instruction straddles cache lines
    address_64 next_addr;
    int remaining_size;
    int offset = get_offset(self, addr);
    if(offset + ins_size >= self->line_size) {
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
    while(line != NULL) {
        // CACHE HIT.
        if (line->tag == tag) {
            if(ins_type == WRITE){
                write_to_line(self, addr, line, ins_size);
            }
            self->hits++; // Record cache hit.
            if(straddle) {
                // If instruction straddles cache line perform lookup on remaining instruction.
                cache_lookup(self, next_addr, ins_type, remaining_size);
            }
            return;
        } else {
            line = line->next;
        }
    }
    // CACHE MISS.
    // Add cache line with current tag to cache.
    add_to_cache(self, tag, index);
    self->misses++; //Record miss.
    // Update dirty bits if instruction is a write.
    if(ins_type == WRITE) {
        write_to_line(self, addr, self->sets[index], ins_size);
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
            if(line->dirty[j] == 1) {
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

/**
 * Frees all the memory allocated to the cache.
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
 * Prints hits and misses. Only for testing purposes.
 * @param self Pointer to cache.
 */
void print_hit_miss(cache *self) {
    printf("Hits: %d\nMisses: %d\n", self->hits, self->misses);
}

/* ================================================================== */
// Global variables 
/* ================================================================== */

cache* myCache;

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 readCount = 0;       //total number of memory reads
UINT64 writeCount = 0;       //total number of memory writes

UINT64 hitCount = 0;
UINT64 missCount = 0;

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for PinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<UINT32> KnobAssociativty(KNOB_MODE_WRITEONCE, "pintool", 
    "a", "2", "Set associativity of cache.");

KNOB<UINT32> KnobLineSize(KNOB_MODE_WRITEONCE, "pintool", 
    "l", "64", "Set cache line size in bytes.");   

KNOB<UINT32> KnobSize(KNOB_MODE_WRITEONCE, "pintool", 
    "s", "8388608", "Set cache size in bytes.");    

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool simulates a cache and prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and reads and writes, cache hits and misses in the application." << endl << endl;

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
 * Increase counter of the executed memory reads and cache hits and misses.
 * This function is called for every memory read when it is about to be executed.
 * @param[in]   ip    address of the read instruction (NOT IN USE)
 * @param[in]   addr  address of the data to be read.
 */
VOID CountMemRead(VOID * ip, VOID * addr, UINT32 size)
{
    //REMOVE COMMENT IF YOU WANT READ ADDRESSES TO BE PRINTED
    //*out << "Memory address read: " << addr << endl;
    
    //*out << "Memory read size: " << size << endl;
    readCount++;
    cache_lookup(myCache, (address_64) addr, READ, (int) size);


}

/*!
 * Increase counter of the executed memory writes and cache hits and misses. 
 * This function is called for every memory write when it is about to be executed.
 * @param[in]   ip    address of the write instruction (NOT IN USE)
 * @param[in]   addr  address of the data to be written.
 */
VOID CountMemWrite(VOID * ip, VOID * addr, UINT32 size)
{
    writeCount++;

    cache_lookup(myCache, (address_64) addr, WRITE, (int) size);
 
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
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CountMemRead, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    else if(INS_IsMemoryWrite(ins))
    {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) CountMemWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
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
    count_dirty_bits(myCache);
    *out <<  "===============================================" << endl;
    *out <<  "PinTool analysis results: " << endl << endl;

    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of reads: " << readCount  << endl;
    *out <<  "Number of writes: " << writeCount  << endl << endl;

    *out <<  "Number of cache read lookups: " << myCache->no_read_lookups << endl;
    *out <<  "Number of cache write lookups: " << myCache->no_write_lookups << endl;
    *out <<  "Number of cache hits: " << myCache->hits << endl;
    *out <<  "Number of cache misses: " << myCache->misses << endl << endl;

    *out <<  "Number of cache line straddles: " << myCache->no_cache_straddles  << endl;
    *out <<  "Number of read cache line straddles: " << myCache->no_read_straddles  << endl;
    *out <<  "Number of write cache line straddles: " << myCache->no_write_straddles  << endl << endl;

    *out <<  "Number of bytes written to memory: " << myCache->no_bytes_written  << endl;
    *out <<  "Number of writes to memory: " << myCache->no_mem_writes  << endl;
    *out <<  "Number of cache line evictions: " <<  myCache->no_evicts  << endl << endl;

    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "===============================================" << endl;

    delete_cache(myCache);
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

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

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
    if (!is_power_of_two(KnobSize) || !is_power_of_two(KnobLineSize) || 
        !is_power_of_two(KnobAssociativty))
    {
        cerr << "Error: Size of cache, chache line size and associativity each need" 
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
    
    // Initializes cache simulation
    myCache = create_cache(KnobSize, KnobLineSize, KnobAssociativty);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
