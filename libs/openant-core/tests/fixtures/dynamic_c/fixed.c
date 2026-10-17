#include <stdlib.h>
/* 与漏洞版本相同的输入，先检查边界。 */
int inspect_index(int index) {
    if (index < 0 || index >= 4) return -1;
    int *values = malloc(4 * sizeof(*values));
    if (!values) return -2;
    for (int i = 0; i < 4; ++i) values[i] = i;
    int value = values[index];
    free(values);
    return value;
}
