import hashlib
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR, pair


class MPACryptoPrimitives:
    def __init__(self, curve_name='BN254'):
        """
        初始化 254 位 Type-III 配对群。
        """
        try:
            self.group = PairingGroup(curve_name)
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize pairing group {curve_name}. Ensure Charm-Crypto and PBC are installed correctly. Error: {e}")

        # 选取群 G1 和 G2 的随机生成元
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

    def hash_to_g1(self, data: str):
        """
        将任意字符串数据映射到群 G1 上的元素。
        这对应于论文中生成多副本标签时的哈希操作。
        """
        if not isinstance(data, str):
            data = str(data)
        return self.group.hash(data, G1)

    def standard_hash(self, data: str) -> str:
        """
        标准的 SHA-256 哈希函数，返回十六进制字符串。
        用于生成默克尔树的非叶子节点哈希。
        """
        if not isinstance(data, str):
            data = str(data)
        sha256 = hashlib.sha256()
        sha256.update(data.encode('utf-8'))
        return sha256.hexdigest()

    def pairing(self, element_g1, element_g2):
        """
        计算双线性配对 e(u, v)。
        核心操作，用于验证多项式承诺和最终的审计聚合证明。
        """
        return pair(element_g1, element_g2)

    def exp_g1(self, base, exponent):
        """
        在群 G1 上的模幂运算 (标量乘法)。
        """
        return base ** exponent

    def exp_g2(self, base, exponent):
        """
        在群 G2 上的模幂运算。
        """
        return base ** exponent

    def random_zr(self):
        """
        从有限域 ZR 中选取一个随机数。
        用于生成随机挑战等操作。
        """
        return self.group.random(ZR)


# 简单的测试逻辑
if __name__ == "__main__":
    try:
        crypto = MPACryptoPrimitives()
        print("配对群初始化成功！")

        test_str = "MPA_Auditing_Test"

        h_g1 = crypto.hash_to_g1(test_str)
        print(f"'{test_str}' 映射到 G1: {h_g1}")

        std_h = crypto.standard_hash(test_str)
        print(f"'{test_str}' 的 SHA-256 哈希: {std_h}")

        # 测试双线性映射性质: e(g1^a, g2^b) == e(g1, g2)^(a*b)
        a = crypto.random_zr()
        b = crypto.random_zr()

        g1_a = crypto.exp_g1(crypto.g1, a)
        g2_b = crypto.exp_g2(crypto.g2, b)

        pair1 = crypto.pairing(g1_a, g2_b)
        pair2 = crypto.pairing(crypto.g1, crypto.g2) ** (a * b)

        if pair1 == pair2:
            print("双线性映射性质测试通过！")
        else:
            print("双线性映射性质测试失败！")

    except Exception as e:
        print(f"测试过程中出现错误: {e}")