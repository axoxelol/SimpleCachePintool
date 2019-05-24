# SimpleCachePintool
A Pintool based on MyPinTool with a simple cache simulator for analysing application's memory operations.

## Known issues:
If running an applications which writes its output to the terminal you need to use the -o flag to redirect this tool's output 
to a file. 

## Commandline switches:
**-a**  [default 2] _Set associativity of cache._

**-count**  [default 1]
	_count instructions, basic blocks and threads in the application_
	
	
**-h**  [default 0]
	_Print help message (Return failure of PIN_Init() in order to allow the
	tool                             to print help message)_
	
	
**-help**  [default 0]
	_Print help message (Return failure of PIN_Init() in order to allow the
	tool                             to print help message)_
	
	
**-l**  [default 64]
	_Set cache line size in bytes._
	
	
**-logfile**  [default pintool.log]
	_The log file path and file name_
	
	
**-o**  [default ]
	_specify file name for PinTool output_
	
	
**-s**  [default 8388608]
	_Set cache size in bytes._
	
	
**-unique_logfile**  [default 0]
	_The log file names will contain the pid_

