#include <stdlib.h>
#include <stdio.h>

int main()
{
    printf("Running run_command binary!\n");
    FILE *fp;
    char path[10];
    fp = popen("/usr/bin/optee_hot_cache 123123123123 111111111111", "r");
    if (fp == NULL)
        printf("Error opening the pipe!\n");
    while (fgets(path, 10, fp) != NULL)
    {
        printf("%s", path);
    }
    pclose(fp);
    return 0;
}
