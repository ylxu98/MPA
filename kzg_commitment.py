from crypto_primitives import MPACryptoPrimitives
from charm.toolbox.pairinggroup import ZR, G1, pair


class KZGCommitment:
    def __init__(self, crypto_primitives: MPACryptoPrimitives, max_degree: int):
        self.crypto = crypto_primitives
        self.max_degree = max_degree
        self.srs_g1 = []
        self.srs_g2 = []
        self._setup()

    def _setup(self):
        alpha = self.crypto.random_zr()

        for i in range(self.max_degree + 1):
            self.srs_g1.append(self.crypto.g1 ** (alpha ** i))

        self.srs_g2.append(self.crypto.g2)
        self.srs_g2.append(self.crypto.g2 ** alpha)

    def commit(self, coefficients):
        if len(coefficients) > self.max_degree + 1:
            raise ValueError("多项式阶数超过了 SRS 的最大容量")

        commitment = self.crypto.group.init(G1, 1)
        for i, coeff in enumerate(coefficients):
            commitment *= (self.srs_g1[i] ** coeff)

        return commitment

    def evaluate_poly(self, coefficients, z):
        y = self.crypto.group.init(ZR, 0)
        z_power = self.crypto.group.init(ZR, 1)
        for coeff in coefficients:
            y += coeff * z_power
            z_power *= z
        return y

    def _synthetic_division(self, num_coeffs, z):
        q_coeffs = [self.crypto.group.init(ZR, 0)] * (len(num_coeffs) - 1)
        current_val = self.crypto.group.init(ZR, 0)

        for i in range(len(num_coeffs) - 1, 0, -1):
            current_val = num_coeffs[i] + current_val * z
            q_coeffs[i - 1] = current_val

        return q_coeffs

    def create_proof(self, coefficients, z):
        y = self.evaluate_poly(coefficients, z)

        num_coeffs = list(coefficients)
        num_coeffs[0] -= y

        q_coeffs = self._synthetic_division(num_coeffs, z)
        pi = self.commit(q_coeffs)

        return pi, y

    def verify_proof(self, commitment, z, y, pi):
        left_element_g1 = commitment / (self.crypto.g1 ** y)
        left_pairing = pair(left_element_g1, self.srs_g2[0])

        right_element_g2 = self.srs_g2[1] / (self.crypto.g2 ** z)
        right_pairing = pair(pi, right_element_g2)

        return left_pairing == right_pairing


if __name__ == "__main__":
    try:
        crypto = MPACryptoPrimitives()
        max_poly_degree = 5
        kzg = KZGCommitment(crypto, max_poly_degree)
        print("KZG 可信设置初始化成功！")

        poly_coeffs = [crypto.random_zr() for _ in range(max_poly_degree + 1)]
        print("生成随机多项式完成。")

        commitment = kzg.commit(poly_coeffs)
        print("多项式承诺计算完成。")

        z = crypto.random_zr()
        pi, y = kzg.create_proof(poly_coeffs, z)
        print("评估证明生成完成。")

        is_valid = kzg.verify_proof(commitment, z, y, pi)
        if is_valid:
            print("KZG 多项式承诺验证通过！")
        else:
            print("KZG 验证失败！")

    except Exception as e:
        print(f"执行过程中出现错误: {e}")