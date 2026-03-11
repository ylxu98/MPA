import time
import statistics
from crypto_primitives import MPACryptoPrimitives
from mpa_protocol import DataOwner, ThirdPartyAuditor, CloudServer


def run_academic_benchmark():
    crypto_engine = MPACryptoPrimitives()
    # 模拟论文中常见的测试梯度
    block_sizes = [500, 1000, 2000, 5000]
    replica_count = 3
    challenge_size = 50
    # 每个测试点运行5次取平均值，确保论文数据准确
    iterations = 5

    print(f"{'数据块规模':<12} | {'预处理均值(s)':<15} | {'证明生成均值(s)':<15} | {'验证耗时均值(s)':<15}")
    print("-" * 70)

    for size in block_sizes:
        prep_times = []
        proof_times = []
        verify_times = []

        for _ in range(iterations):
            # 1. 预处理
            owner = DataOwner(crypto_engine, size, replica_count)
            raw_data = [crypto_engine.random_zr() for _ in range(size + 1)]

            t1 = time.time()
            reps, tags, trees = owner.process_data(raw_data)
            prep_times.append(time.time() - t1)

            # 2. 挑战与证明
            auditor = ThirdPartyAuditor(crypto_engine)
            challenge_dict, z = auditor.generate_challenge(size + 1, challenge_size)
            cloud = CloudServer(crypto_engine, owner.kzg, reps)

            t2 = time.time()
            mu, pi, y = cloud.generate_proof(0, challenge_dict, z)
            proof_times.append(time.time() - t2)

            # 3. 验证
            t3 = time.time()
            is_valid = auditor.verify_cloud_proof(owner.kzg, tags[0], z, y, pi)
            verify_times.append(time.time() - t3)

        avg_prep = statistics.mean(prep_times)
        avg_proof = statistics.mean(proof_times)
        avg_verify = statistics.mean(verify_times)

        print(f"{size:<14} | {avg_prep:<16.4f} | {avg_proof:<16.4f} | {avg_verify:<16.4f}")


if __name__ == "__main__":
    print("开始生成论文实验数据 (多副本审计协议)...")
    run_academic_benchmark()