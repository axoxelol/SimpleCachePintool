# SimpleCachePintool
A Pintool based on MyPinTool with a simple cache simulator for analysing application's memory operations.

Known issues:
If running an applications which writes its output to the terminal you need to use the -o flag to redirect this tool's output 
to a file. 

Commandline switches:
-a  [default 2]
	Set associativity of cache.
-count  [default 1]
	count instructions, basic blocks and threads in the application
-h  [default 0]
	Print help message (Return failure of PIN_Init() in order to allow the
	tool                             to print help message)
-help  [default 0]
	Print help message (Return failure of PIN_Init() in order to allow the
	tool                             to print help message)
-l  [default 64]
	Set cache line size in bytes.
-logfile  [default pintool.log]
	The log file path and file name
-o  [default ]
	specify file name for PinTool output
-s  [default 8388608]
	Set cache size in bytes.
-unique_logfile  [default 0]
	The log file names will contain the pid

