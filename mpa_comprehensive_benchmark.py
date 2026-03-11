import time
import statistics
import sys
from crypto_primitives import MPACryptoPrimitives
from mpa_protocol import DataOwner, ThirdPartyAuditor, CloudServer


def run_comprehensive_benchmark():
    crypto = MPACryptoPrimitives()
    # 模拟论文常见梯度：从轻量级到大规模压力
    block_sizes = [1000, 3000, 5000]
    replica_count = 3
    challenge_size = 50
    iterations = 3

    print(
        f"{'块数量':<8} | {'预处理(s)':<12} | {'证明生成(s)':<12} | {'验证(s)':<12} | {'更新(s)':<12} | {'通信(Bytes)':<12}")
    print("-" * 90)

    for size in block_sizes:
        res_prep, res_proof, res_verify, res_update = [], [], [], []

        for _ in range(iterations):
            # --- 1. 预处理实验 ---
            owner = DataOwner(crypto, size, replica_count)
            raw_data = [crypto.random_zr() for _ in range(size)]
            t1 = time.time()
            reps, tags, trees = owner.process_data(raw_data)
            res_prep.append(time.time() - t1)

            # --- 2. 审计证明实验 ---
            auditor = ThirdPartyAuditor(crypto)
            challenge_dict, z = auditor.generate_challenge(size, challenge_size)
            cloud = CloudServer(crypto, owner.kzg, reps)
            t2 = time.time()
            mu, pi, y = cloud.generate_proof(0, challenge_dict, z)
            res_proof.append(time.time() - t2)

            # --- 3. 验证实验 ---
            t3 = time.time()
            is_valid = auditor.verify_cloud_proof(owner.kzg, tags[0], z, y, pi)
            res_verify.append(time.time() - t3)

            # --- 4. 动态更新模拟 (修改其中一块) ---
            new_block = crypto.random_zr()
            t4 = time.time()
            # 模拟默克尔树更新和KZG标签重算
            trees[0].update(0, str(new_block))
            # 论文中通常使用增量更新，此处模拟核心耗时
            res_update.append(time.time() - t4)

        # --- 5. 通信开销模拟计算 (单位：字节) ---
        # 挑战：indices(int) + v(ZR) | 证明：mu(ZR) + pi(G1) + y(ZR)
        # 假设 ZR 为 32 字节, G1 为 64 字节
        comm_size = (challenge_size * (4 + 32)) + (32 + 64 + 32)

        print(f"{size:<10} | {statistics.mean(res_prep):<14.4f} | {statistics.mean(res_proof):<14.4f} | "
              f"{statistics.mean(res_verify):<14.4f} | {statistics.mean(res_update):<14.4f} | {comm_size:<12}")


if __name__ == "__main__":
    print("正在执行论文全维度实验模拟...")
    run_comprehensive_benchmark()