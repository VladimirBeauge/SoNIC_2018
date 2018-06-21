#include <stdio.h>
#include <ctype.h>

main(){
	int c = 0;	
	while((c = getchar()) != EOF)
		putchar(tolower(c));	
	
	return 0;
}
