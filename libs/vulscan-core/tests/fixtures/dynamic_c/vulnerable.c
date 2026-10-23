#include <stdlib.h>
/* 仅供本地回归测试：输入索引未经检查。 */
int inspect_index(int index) {
    int *values = malloc(4 * sizeof(*values));
    if (!values) return -2;
    for (int i = 0; i < 4; ++i) values[i] = i;
    int value = values[index];
    free(values);
    return value;
}
