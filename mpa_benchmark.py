import time
from crypto_primitives import MPACryptoPrimitives
from mpa_protocol import DataOwner, ThirdPartyAuditor, CloudServer

def run_benchmark():
    crypto_engine = MPACryptoPrimitives()
    replica_count = 3
    challenge_size = 50
    block_sizes = [100, 200, 300]

    for size in block_sizes:
        print("测试数据块数量:", size)
        owner = DataOwner(crypto_engine, size, replica_count)
        raw_data = [crypto_engine.random_zr() for _ in range(size + 1)]

        start_time = time.time()
        reps, tags, trees = owner.process_data(raw_data)
        end_time = time.time()
        print("预处理与标签生成耗时(秒):", end_time - start_time)

        auditor = ThirdPartyAuditor(crypto_engine)
        challenge_dict, z = auditor.generate_challenge(size + 1, challenge_size)
        cloud = CloudServer(crypto_engine, owner.kzg, reps)

        start_time = time.time()
        mu, pi, y = cloud.generate_proof(0, challenge_dict, z)
        end_time = time.time()
        print("云服务器生成证明耗时(秒):", end_time - start_time)

        start_time = time.time()
        is_valid = auditor.verify_cloud_proof(owner.kzg, tags[0], z, y, pi)
        end_time = time.time()
        print("双线性配对验证耗时(秒):", end_time - start_time)
        print("---")

if __name__ == "__main__":
    run_benchmark()