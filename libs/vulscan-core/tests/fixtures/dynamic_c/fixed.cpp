#include <vector>
// 与漏洞版本相同的输入，先检查边界。
int inspect_index(int index) {
    std::vector<int> values{0, 1, 2, 3};
    if (index < 0 || static_cast<std::size_t>(index) >= values.size()) return -1;
    return values[index];
}
