import math
from crypto_primitives import MPACryptoPrimitives


class DynamicMerkleNode:
    def __init__(self, hash_val, left=None, right=None, parent=None, is_leaf=False, rank=1):
        self.hash_val = hash_val
        self.left = left
        self.right = right
        self.parent = parent
        self.is_leaf = is_leaf
        self.rank = rank


class DynamicMerkleTree:
    def __init__(self, crypto_primitives: MPACryptoPrimitives):
        self.crypto = crypto_primitives
        self.root = None
        self.leaves = []
        self.num_leaves = 0

    def _hash_nodes(self, left_hash, right_hash):
        combined = str(left_hash) + str(right_hash)
        return self.crypto.standard_hash(combined)

    def build_tree(self, data_blocks):
        self.num_leaves = len(data_blocks)
        self.leaves = []
        for block in data_blocks:
            leaf_hash = self.crypto.standard_hash(str(block))
            leaf_node = DynamicMerkleNode(hash_val=leaf_hash, is_leaf=True, rank=1)
            self.leaves.append(leaf_node)
        self.root = self._build_recursive(self.leaves)

    def _build_recursive(self, nodes):
        if not nodes: return None
        if len(nodes) == 1: return nodes[0]
        parent_nodes = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            if i + 1 < len(nodes):
                right = nodes[i + 1]
                parent_hash = self._hash_nodes(left.hash_val, right.hash_val)
                parent = DynamicMerkleNode(hash_val=parent_hash, left=left, right=right, rank=left.rank + right.rank)
                left.parent = parent
                right.parent = parent
            else:
                parent = left
            parent_nodes.append(parent)
        return self._build_recursive(parent_nodes)

    def update(self, index, new_data):
        if not self.root or index >= self.num_leaves: return

        depth = math.ceil(math.log2(self.num_leaves)) if self.num_leaves > 1 else 0
        path = bin(index)[2:].zfill(depth)
        node = self.root
        for bit in path:
            node = node.right if bit == '1' and node.right else node.left

        node.hash_val = self.crypto.standard_hash(str(new_data))
        while node.parent:
            node = node.parent
            left_val = node.left.hash_val if node.left else ""
            right_val = node.right.hash_val if node.right else ""
            node.hash_val = self._hash_nodes(left_val, right_val)

    def get_root_hash(self):
        return self.root.hash_val if self.root else None


if __name__ == "__main__":
    try:
        crypto = MPACryptoPrimitives()
        merkle_tree = DynamicMerkleTree(crypto)
        print("动态秩默克尔树类初始化成功！")

        test_blocks = ["block_0_data", "block_1_data", "block_2_data", "block_3_data", "block_4_data"]
        merkle_tree.build_tree(test_blocks)

        if merkle_tree.root:
            print("默克尔树构建完成！")
            print("根节点哈希值:", merkle_tree.root.hash_val)
            print("根节点秩 (包含的数据块总数):", merkle_tree.root.rank)

            # 额外验证一次更新功能
            print("\n正在模拟修改 block_0 ...")
            merkle_tree.update(0, "new_block_0_data")
            print("更新后的根节点哈希值:", merkle_tree.root.hash_val)
        else:
            print("默克尔树构建失败！")

    except Exception as e:
        print("执行过程中出现错误:", e)