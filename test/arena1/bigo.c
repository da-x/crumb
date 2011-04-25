#include <stdio.h>

#define X a_func_call();
#define X2 X X
#define X3 X2 X2
#define X4 X3 X3
#define X5 X4 X4
#define X6 X5 X5
#define X7 X6 X6
#define X8 X7 X7
#define X9 X8 X8
#define X10 X9 X9
#define X11 X10 X10
#define X12 X11 X11
#define X13 X12 X12
#define X14 X13 X13

void a_func_call()
{
	printf("Hello\n");
}

void big_o_func()
{
	X13;
}
