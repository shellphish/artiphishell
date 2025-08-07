#include <stdio.h>
#include <string.h>
#include <unistd.h>

char items[3][10];

void func_a(){
    char* buff;
    int i = 0;
    do{
        printf("input item:");
        buff = &items[i][0];
        i++;
        fgets(buff, 40, stdin);
        buff[strcspn(buff, "\n")] = 0;
    }while(strlen(buff)!=0);
    i--;
}

void func_b(){                                                                                                                                                                                                                                       
    char *buff;                                                                                                                                                                                                                                      
    printf("done adding items\n");                                                                                                                                                                                                                   
    int j;                                                                                                                                                                                                                                           
    printf("display item #:");                                                                                                                                                                                                                       
    scanf("%d", &j);                                                                                                                                                                                                                                 
    if (j < 0 || j >= 3) {                                                                                                                                                                                                                           
        printf("Invalid item number\n");                                                                                                                                                                                                             
        return;                                                                                                                                                                                                                                      
    }                                                                                                                                                                                                                                                
    buff = &items[0];                                                                                                                                                                                                                                
    printf("item %d: %s\n", j, buff);                                                                                                                                                                                                                
}


#ifndef ___TEST___
int main()
{

    func_a();

    func_b();


    return 0;
}
#endif
