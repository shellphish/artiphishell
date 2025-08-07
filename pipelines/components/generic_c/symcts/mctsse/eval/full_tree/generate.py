import sys
import random
from collections import namedtuple
template = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    unsigned char buf[0x1000];
    memset(buf, 0, 0x1000);
    int num_chars = read(0, buf, 0x1000);

'''

class TreeNode(namedtuple("TreeNode", 'path weight left right')):
    __slots__ = ()

    @classmethod
    def deserialize(cls, o):
        return cls(**o)

    def serialize(self):
        return tuple(self)

    @property
    def prob_left(self):
        return self.weight // 256

    @property
    def prob_right(self):
        return (256 - self.weight)

    def __str__(self, indent=0):
        pre = ' ' * indent
        buf_idx = len(self.path)
        s = pre + f'if (buf[{buf_idx}] < {self.weight}) ' + '{\n'
        s += pre + ' puts("left");\n'
        subtree_left = None
        if self.left is not None:
            subtree_left = self.left.__str__(indent=indent+1)
            s += subtree_left + '\n'
        s += pre + '} else {' + '\n'
        s += pre + ' puts("right");\n'
        if self.right is not None:
            s += self.right.__str__(indent=indent+1) + '\n'
        s += pre + '}'
        return s

rand = random.Random(1337)

def random_tree(depth=20, path='', child_prob=1.0):
    if depth == 0:
        return None
    alpha = random.randint(0, 255)
#    alpha = 32
    left, right = None, None
    if rand.random() <= child_prob:
        left = random_tree(depth-1, path+'l', child_prob)
    if rand.random() <= child_prob:
        right = random_tree(depth-1, path+'r', child_prob)
    return TreeNode(path, alpha, left, right)

code = template + random_tree(depth=int(sys.argv[1])).__str__(indent=1) + '\n}'

with open(f'target.c', 'w') as f:
    f.write(code)

