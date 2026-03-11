from charm.toolbox.pairinggroup import ZR
from crypto_primitives import MPACryptoPrimitives
from kzg_commitment import KZGCommitment
from dynamic_merkle_tree import DynamicMerkleTree
import random

class DataOwner:
    def __init__(self, crypto_primitives, max_degree, num_replicas):
        self.crypto = crypto_primitives
        self.kzg = KZGCommitment(self.crypto, max_degree)
        self.num_replicas = num_replicas

    def generate_replicas(self, original_blocks):
        replicas = []
        for i in range(self.num_replicas):
            replica_blocks = []
            for block in original_blocks:
                offset = self.crypto.group.init(ZR, i + 1)
                replica_block = block + offset
                replica_blocks.append(replica_block)
            replicas.append(replica_blocks)
        return replicas

    def process_data(self, original_blocks):
        replicas = self.generate_replicas(original_blocks)

        replica_tags = []
        merkle_trees = []

        for idx, replica_blocks in enumerate(replicas):
            tag = self.kzg.commit(replica_blocks)
            replica_tags.append(tag)

            tree = DynamicMerkleTree(self.crypto)
            str_blocks = [str(b) for b in replica_blocks]
            tree.build_tree(str_blocks)
            merkle_trees.append(tree)

        return replicas, replica_tags, merkle_trees


class ThirdPartyAuditor:
    def __init__(self, crypto_primitives):
        self.crypto = crypto_primitives

    def generate_challenge(self, total_blocks, challenge_size):
        if challenge_size > total_blocks:
            raise ValueError("挑战块数量不能超过总数据块数量")

        indices = random.sample(range(total_blocks), challenge_size)
        challenge_dict = {}
        for i in indices:
            challenge_dict[i] = self.crypto.random_zr()

        z = self.crypto.random_zr()
        return challenge_dict, z

    def verify_cloud_proof(self, kzg_instance, commitment, z, y, pi):
        return kzg_instance.verify_proof(commitment, z, y, pi)


class CloudServer:
    def __init__(self, crypto_primitives, kzg_commitment, replicas):
        self.crypto = crypto_primitives
        self.kzg = kzg_commitment
        self.replicas = replicas

    def generate_proof(self, replica_index, challenge_dict, z):
        target_replica = self.replicas[replica_index]

        mu = self.crypto.group.init(ZR, 0)
        for idx, v in challenge_dict.items():
            mu += v * target_replica[idx]

        pi, y = self.kzg.create_proof(target_replica, z)

        return mu, pi, y

if __name__ == "__main__":
    try:
        crypto_engine = MPACryptoPrimitives()
        sectors_per_replica = 5
        replica_count = 3
        challenge_size = 2

        owner = DataOwner(crypto_engine, sectors_per_replica, replica_count)
        print("数据拥有者初始化完成，系统参数已就绪。")

        raw_data_blocks = [crypto_engine.random_zr() for _ in range(sectors_per_replica + 1)]
        print("原始文件分块模拟完成。")

        reps, tags, trees = owner.process_data(raw_data_blocks)
        print("多副本生成与同态标签计算完成。")

        auditor = ThirdPartyAuditor(crypto_engine)
        challenge_dict, z = auditor.generate_challenge(sectors_per_replica + 1, challenge_size)
        print("第三方验证者发起随机挑战成功。")

        cloud = CloudServer(crypto_engine, owner.kzg, reps)
        target_replica_idx = 0
        mu, pi, y = cloud.generate_proof(target_replica_idx, challenge_dict, z)
        print("云服务器生成审计证明完成。")

        is_valid = auditor.verify_cloud_proof(owner.kzg, tags[target_replica_idx], z, y, pi)
        if is_valid:
            print("完整性审计通过！云端数据完好无损。")
        else:
            print("审计失败！云端数据可能遭到篡改。")

    except Exception as e:
        print("协议执行过程中出现错误:", e)
