#include <lwip/opt.h>
#include <lwip/sys.h>
#include <time.h>

int atoi(const char *str) { 
    int res = 0; 
	
    for (int i = 0; str[i] >= '0' && str[i] <= '9' ; i++)
		res = res * 10 + str[i] - '0'; 
	
    return res; 
}
	
u32_t sys_now(void) {
	return get_timer(0);
}