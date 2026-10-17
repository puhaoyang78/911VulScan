#include <vector>
// 仅供本地回归测试：输入索引未经检查。
int inspect_index(int index) {
    std::vector<int> values{0, 1, 2, 3};
    return values[index];
}
