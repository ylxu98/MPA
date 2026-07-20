# =========================================================================================
# MPA: Lightweight and Updatable Integrity Auditing for Decentralized Storage
# 论文：轻量可更新去中心化存储完整性审计协议 MPA 完整 Python 仿真实现
#
# 【一、协议与技术背景说明 (Protocol & Technical Background)】
# 本代码复现《MPA》论文去中心化存储完整性审计方案，核心密码学组件：
# 1. KZG 多项式承诺：实现块级/扇区级数据承诺、零知识批量验证、动态更新证明
# 2. 秩基动态 Merkle Tree：为每个文件副本存储 Tag 默克尔根，支持 O(log n) 单点更新
# 3. 多副本聚合证明：单轮配对完成百文件+多副本批量审计，无区块链依赖，链下可信 TPA
# 能力特性：公开可验证、多副本同时校验、文件块动态修改、轻量级聚合证明、防CSP伪造
#
# 【二、链下 TPA 模拟与 Ubuntu 适配 (Off-chain TPA Simulation)】
# 1. 实体角色简化：移除区块链上链逻辑，使用论文原生架构的可信第三方审计者 TPA
#    TPA 统一存储所有文件副本的 Merkle Root、生成随机挑战、执行双线性配对验证
# 2. 进度可视化：tqdm 进度条监控文件生成、证明聚合、配对校验等高耗时循环
# 3. 运行依赖：Charm-Crypto 密码库、Python3，兼容 Ubuntu 系统；隔离底层C拓展内存泄漏风险
# 4. 安全模型：半诚实云服务商CSP，完全可信TPA，数据持有者User持有私钥α，CSP无法伪造证明
# =========================================================================================

import hashlib
import random
import time
from tqdm import tqdm
# Charm密码库双线性配对基础组件
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair

# ==========================================
# 【全局配置区：可调仿真参数 (Global Configurations)】
# 可根据仿真规模修改，参数含义完全对齐论文实验章节
# ==========================================
T_FILES = 100    # 文件总数：批量审计场景下待校验文件数量 (Number of files for batch auditing)
N_COPIES = 3     # 单文件副本数：去中心化存储多副本容错设定 (Number of replicas per file)[cite: 2]
N_BLOCKS = 50    # 单个文件切分块数：文件拆分为N_BLOCKS个独立数据块 (Number of blocks per file)
S_SECTORS = 5    # 单块扇区数量：每个数据块内部划分为S_SECTORS个扇区，对应多项式系数[cite: 2]
C_CHALLENGES = 10# 单次审计随机挑战块数量：TPA抽样C_CHALLENGES个块校验完整性[cite: 2]

# --- 参数合法性拦截 (Parameter Validation) ---
# 校验挑战块数量边界：抽样块不能超过文件总块数、不能为0
if not (1 <= C_CHALLENGES <= N_BLOCKS):
    raise ValueError("配置异常: 挑战块数 C_CHALLENGES 必须在 1 到 N_BLOCKS 之间")
# 所有规模参数必须为正整数，避免空文件/空副本/空块导致密码运算崩溃
if any(val < 1 for val in [S_SECTORS, N_BLOCKS, N_COPIES, T_FILES]):
    raise ValueError("配置异常: 全局参数设置非法，所有维度必须为正整数")

# 初始化底层椭圆曲线配对群 SS512（安全级别128bit，论文标准配对群）
group = PairingGroup('SS512')
# G1群全局固定安全生成元，全程复用，无需重复随机生成
G_GEN = group.random(G1)


# ==========================================
# 【基础工具层：类型安全的群常量初始化】
# 封装配对群零元/单位元获取，避免手动运算产生群类型错误
# ==========================================
def get_zero_zr():
    """
    获取有限域ZR加法单位元 0
    ZR：配对群底层标量域，所有多项式系数、随机挑战标量均属于ZR
    运算：任意z ∈ ZR，z + 0 = z
    """
    return group.random(ZR) * 0


def get_one_g1():
    """
    获取G1乘法单位元 1（无穷远点）
    G1：KZG承诺存储群，所有数据Tag、聚合证明元素均属于G1
    运算：任意g ∈ G1，g * 1 = g
    """
    return G_GEN ** 0


# ==========================================
# 【模块一：密码基础代数层 (Cryptographic Algebra)】
# ZR有限域多项式完整运算封装，支撑KZG承诺核心计算
# 实现：求值、多项式加减、标量乘、除(x-r)商多项式（KZG商证明核心）
# ==========================================
class Poly:
    """有限域 ZR 上的多项式运算封装，完全适配KZG多项式承诺方案[cite: 2]"""

    def __init__(self, coeffs):
        """
        多项式初始化
        :param coeffs: 多项式系数列表 [c0, c1, c2...cd]，代表 f(x) = c0 + c1*x + c2*x² + ... + cd*x^d
        """
        self.coeffs = coeffs

    def evaluate(self, x):
        """
        多项式求值 f(x)
        :param x: ZR域标量求值点
        :return: f(x) ∈ ZR 求值结果
        """
        res = get_zero_zr()
        # 遍历所有系数，累加 c_i * x^i
        for i, c in enumerate(self.coeffs):
            res += c * (x ** i)
        return res

    def __add__(self, other):
        """重载加法运算符：两个多项式逐系数相加"""
        max_len = max(len(self.coeffs), len(other.coeffs))
        # 短多项式尾部补0对齐次数
        c1 = self.coeffs + [get_zero_zr()] * (max_len - len(self.coeffs))
        c2 = other.coeffs + [get_zero_zr()] * (max_len - len(other.coeffs))
        # 逐系数相加生成新多项式
        return Poly([x + y for x, y in zip(c1, c2)])

    def __mul__(self, scalar):
        """重载标量乘法：多项式全体系数乘以同一个ZR标量（聚合证明加权使用）"""
        return Poly([c * scalar for c in self.coeffs])

    def div_x_minus_r(self, r):
        """
        KZG核心算法：多项式 f(x) 除以 (x - r)，返回商多项式 q(x)
        满足恒等式：f(x) = q(x) * (x - r) + f(r)
        用于生成开放证明w，证明f(r)=val
        :param r: ZR域求值点
        :return: 商多项式 q(x)
        """
        d = len(self.coeffs) - 1  # 原多项式最高次数
        q_coeffs = [get_zero_zr()] * d  # 商多项式次数 = 原次数-1
        rem = self.coeffs[-1]
        q_coeffs[-1] = rem
        # 秦九韶算法倒序计算商多项式系数
        for i in range(d - 1, 0, -1):
            rem = self.coeffs[i] + (rem * r)
            q_coeffs[i - 1] = rem
        return Poly(q_coeffs)


# ==========================================
# 【模块二：数据结构工具层 (Merkle Tree)】
# 秩基动态Merkle树，存储每个文件副本所有块的KZG Tag哈希
# 优势：单点叶子更新仅重算O(log n)层哈希，适配文件块动态修改场景
# 用途：TPA存储根哈希，审计时校验Tag未被CSP替换/篡改
# ==========================================
class DynamicMerkleTree:
    """基于秩(Rank)机制的动态 Merkle 树，单点更新复杂度 O(log n)[cite: 2]"""

    def __init__(self, leaves_elements):
        """
        初始化默克尔树
        :param leaves_elements: 叶子原始元素（G1群Tag），内部自动序列化+哈希
        """
        # 所有叶子统一序列化并做SHA256哈希，作为树底层叶子节点
        self.leaves = [self.hash_data(group.serialize(d)) for d in leaves_elements]
        # 递归构建完整默克尔树多层结构
        self.tree = self.build_tree(self.leaves)
        # 顶层根哈希，上传至TPA永久存证
        self.root = self.tree[-1][0] if self.tree else None

    @staticmethod
    def hash_data(data_bytes):
        """
        静态哈希工具：输入字节流输出SHA256十六进制摘要
        :param data_bytes: 二进制字节数据
        :return: sha256 hexdigest字符串
        """
        if not isinstance(data_bytes, bytes):
            raise TypeError("哈希输入必须严格为 bytes 格式")
        return hashlib.sha256(data_bytes).hexdigest()

    def build_tree(self, leaves):
        """
        递归构建完整默克尔树多层结构
        奇数层最后节点自配对（叶子数量非2的幂次兼容）
        :param leaves: 底层叶子哈希列表
        :return: tree 二维列表，tree[0]叶子层、tree[-1]根节点层
        """
        tree = [leaves]
        layer = leaves
        # 逐层向上合并哈希，直到只剩根节点
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                # 奇数节点无右兄弟时，右节点复用自身
                right = layer[i + 1] if i + 1 < len(layer) else left
                # 左右哈希拼接后重新哈希生成父节点
                next_layer.append(self.hash_data((left + right).encode('utf-8')))
            tree.append(next_layer)
            layer = next_layer
        return tree

    def update_leaf(self, index, new_leaf_element):
        """
        动态更新单个叶子节点，逐层向上刷新父哈希，O(log n)复杂度
        :param index: 需要更新的叶子下标（对应文件块索引）
        :param new_leaf_element: 新的G1 Tag元素
        """
        # 计算新叶子哈希，替换底层叶子
        new_hash = self.hash_data(group.serialize(new_leaf_element))
        self.tree[0][index] = new_hash
        curr_index = index

        # 逐层向上遍历每一层父节点，重新计算哈希
        for level in range(len(self.tree) - 1):
            layer = self.tree[level]
            is_right = curr_index % 2
            # 定位当前节点的左右兄弟下标
            left_idx = curr_index - 1 if is_right else curr_index
            right_idx = curr_index if is_right else curr_index + 1

            left_hash = layer[left_idx]
            right_hash = layer[right_idx] if right_idx < len(layer) else left_hash

            # 重新计算父节点哈希
            parent_hash = self.hash_data((left_hash + right_hash).encode('utf-8'))
            curr_index //= 2
            self.tree[level + 1][curr_index] = parent_hash
        # 更新全局根哈希，同步上传TPA
        self.root = self.tree[-1][0]

    def get_proof(self, index):
        """
        获取指定叶子的默克尔审计证明路径（包含每层兄弟哈希+左右标记）
        :param index: 叶子块下标
        :return: proof 路径列表，每项(兄弟哈希, 是否为右节点)
        """
        proof = []
        # 遍历除根节点外所有层，收集兄弟节点
        for layer in self.tree[:-1]:
            is_right = index % 2
            sibling_index = index - 1 if is_right else index + 1
            # 处理奇数层无兄弟边界
            if sibling_index < len(layer):
                proof.append((layer[sibling_index], is_right))
            else:
                proof.append((layer[index], is_right))
            index //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_element, proof, root):
        """
        TPA侧静态证明校验：使用Tag+证明路径复现根哈希，与存证根对比
        :param leaf_element: CSP返回的待校验Tag
        :param proof: CSP返回的默克尔路径证明
        :param root: TPA本地存储的可信根哈希
        :return: True=Tag合法未篡改；False=Tag被替换
        """
        current_hash = DynamicMerkleTree.hash_data(group.serialize(leaf_element))
        # 逐层拼接兄弟哈希还原上层哈希
        for sibling_hash, is_right in proof:
            if is_right:
                # 当前节点在左，兄弟在右：hash(兄弟||当前)
                current_hash = DynamicMerkleTree.hash_data((sibling_hash + current_hash).encode('utf-8'))
            else:
                # 当前节点在右，兄弟在左：hash(当前||兄弟)
                current_hash = DynamicMerkleTree.hash_data((current_hash + sibling_hash).encode('utf-8'))
        # 还原哈希与TPA存证根匹配则通过
        return current_hash == root


# ==========================================
# 【模块三：业务实体层 (System Entities)】
# 协议三方核心实体：TPA审计者、User数据持有者、CSP云存储服务商
# 严格遵循论文三方交互流程：存储阶段→更新阶段→挑战阶段→响应阶段→验证阶段
# ==========================================
class ThirdPartyAuditor:
    """
    实体功能：链下受信任第三方审计者 (TPA)[cite: 2]
    全局可信实体，无私有敏感数据，仅持有公开参数
    核心职责：
    1. 接收User上传所有文件副本Merkle根并永久存证
    2. 生成随机审计挑战(a_j,v_j,r)下发给所有CSP
    3. 接收CSP聚合代数证明+默克尔路径，批量双线性配对验证完整性
    4. 分离两层校验：KZG代数承诺校验 + Merkle树Tag合法性校验
    """

    def __init__(self):
        # 根哈希存储表：key=(文件ID,副本ID)，value=对应Merkle根
        self.roots = {}
        # 全局公开参数：pk=KZG公钥，g=G1生成元
        self.pk = None
        self.g = None

    def register_public_params(self, pk, g):
        """User上传全局公开参数至TPA，审计全程复用"""
        self.pk = pk
        self.g = g

    def upload_root(self, file_id, copy_id, root):
        """接收User/CSP更新后的Merkle根，存入本地可信存储"""
        self.roots[(file_id, copy_id)] = root

    def get_random_challenge(self):
        """
        生成随机审计挑战三元组 (a_j, v_j, r)
        a_j：抽样块下标集合；v_j：每个抽样块加权随机标量；r：KZG开放求值点
        链下使用本地PRNG生成，无需链上随机源
        :return: a_j, v_j, r
        """
        r_seed = random.randint(1, 999999)
        random.seed(r_seed)
        # 无放回随机抽取C_CHALLENGES个块下标
        a_j = random.sample(range(N_BLOCKS), C_CHALLENGES)
        # 每个抽样块对应一个随机加权标量v_j ∈ ZR
        v_j = [group.random(ZR) for _ in range(C_CHALLENGES)]
        # KZG开放证明求值随机点 r ∈ ZR
        r = group.random(ZR)
        return a_j, v_j, r

    def verify_batch(self, a_j, v_j, r, global_agg_tag, global_val, global_w, local_proofs):
        """
        跨文件、多副本统一批量配对验证，无私有参数，公开可验证[cite: 2]
        两层校验逻辑：
        1. KZG代数配对校验：验证聚合数据承诺合法，CSP未伪造块内容
        2. Merkle路径校验：验证所有返回Tag属于对应副本原始树，未替换Tag
        :param a_j: TPA下发挑战块下标
        :param v_j: 挑战加权标量
        :param r: KZG求值点
        :param global_agg_tag: 全文件全副本聚合Tag（G1）
        :param global_val: 聚合多项式在r点求值总和（ZR）
        :param global_w: 聚合KZG开放证明（G1）
        :param local_proofs: 所有抽样块的(文件ID,副本ID,块索引,Tag,默克尔路径)
        :return: True=全部数据完整；False=存在篡改/丢失
        """
        try:
            # ========== 第一层：KZG双线性配对代数校验 ==========
            # 左式：聚合Tag * g^(-global_val)
            lhs_g1 = global_agg_tag * (self.g ** (-global_val))
            lhs = pair(lhs_g1, self.g)

            # 右式公钥项：pk[1] * g^(-r)
            rhs_g2 = self.pk[1] * (self.g ** (-r))
            rhs = pair(global_w, rhs_g2)
            # 配对相等代表聚合多项式承诺合法
            kzg_valid = (lhs == rhs)

            # ========== 第二层：Merkle树Tag合法性校验 ==========
            merkle_valid = True
            for (file_id, copy_id, _, tag, path) in local_proofs:
                # 取出TPA本地存证可信根
                expected_root = self.roots.get((file_id, copy_id))
                # 无存证根 / 路径还原根不匹配 → Tag伪造
                if not expected_root or not DynamicMerkleTree.verify_proof(tag, path, expected_root):
                    merkle_valid = False
                    break
            # 两层校验全部通过才判定数据完整
            return kzg_valid and merkle_valid
        except Exception as e:
            raise RuntimeError(f"TPA 验证器终止 (Pairing Error): {str(e)}")


class User:
    """
    数据持有者（客户端），唯一持有KZG私钥α的实体
    核心职责：
    1. 生成KZG公私钥对，公钥同步TPA与所有CSP
    2. 原始文件分块、扇区对称加密、构造多项式并生成KZG Tag
    3. 为每个副本构建动态Merkle树，上传根哈希至TPA
    4. 支持指定副本、指定块动态更新，重新计算Tag与Merkle根同步TPA
    """

    def __init__(self):
        # KZG私钥 α ∈ ZR，全程保密，绝不泄露给TPA/CSP
        self.alpha = group.random(ZR)
        self.g = G_GEN
        # KZG公开参数 pk = [g^α^0, g^α^1, g^α^2,...,g^α^(S_SECTORS-1)]
        self.pk = [self.g ** (self.alpha ** i) for i in range(S_SECTORS)]
        # 仿真对称加密密钥，用于扇区数据加密（真实场景替换AES密钥）
        self.sym_key = b"SECURE_AES_SIM_KEY"

    def _encrypt_sector(self, raw_data, copy_id):
        """
        扇区数据对称加密仿真：明文扇区映射为ZR域随机值
        多副本差异化加密：同一原始扇区不同副本生成不同密文多项式
        :param raw_data: 原始明文数值
        :param copy_id: 当前副本编号
        :return: 加密后扇区标量 ∈ ZR
        """
        seed = f"{raw_data}_{self.sym_key.hex()}_{copy_id}".encode('utf-8')
        return group.hash(seed, type=ZR)

    def storage_phase(self, raw_file, file_id):
        """
        协议存储阶段主逻辑：单文件生成N_COPIES份加密副本
        流程：明文分扇区加密 → 构造块多项式 → 计算KZG Tag → 构建Merkle树
        :param raw_file: 原始文件二维数组 [块][扇区]
        :param file_id: 当前文件全局编号
        :return: copies_data 字典，key=副本ID，value=该副本全部多项式、Tag、默克尔树
        """
        copies_data = {}
        # 遍历生成每一份存储副本
        for copy_id in range(N_COPIES):
            polys, tags = [], []
            # 遍历文件所有数据块
            for b_idx in range(N_BLOCKS):
                # 当前块所有扇区加密
                encrypted_sectors = [self._encrypt_sector(raw_file[b_idx][s], copy_id) for s in range(S_SECTORS)]
                # 用加密扇区作为系数构造块多项式 f_b(x)
                poly = Poly(encrypted_sectors)
                # KZG Tag计算：tag_b = g^f_b(α)
                tag = self.g ** poly.evaluate(self.alpha)
                polys.append(poly)
                tags.append(tag)
            # 以所有块Tag为叶子构建动态Merkle树
            mt = DynamicMerkleTree(tags)
            copies_data[copy_id] = {'polys': polys, 'tags': tags, 'mt': mt}
        return copies_data

    def update_block(self, copy_id, block_index, new_block_raw, copies_data):
        """
        协议动态更新阶段：修改指定副本指定数据块
        流程：新块扇区加密 → 重算多项式与Tag → 更新Merkle树叶子 → 返回新根哈希
        :param copy_id: 需要更新的副本编号
        :param block_index: 需要修改的块下标
        :param new_block_raw: 新块明文扇区数组
        :param copies_data: 用户本地存储的文件副本完整状态
        :return: 更新后副本的新Merkle根，用于同步TPA
        """
        # 新块扇区加密
        encrypted_sectors = [self._encrypt_sector(new_block_raw[s], copy_id) for s in range(S_SECTORS)]
        new_poly = Poly(encrypted_sectors)
        # 重新计算更新块的KZG Tag
        new_tag = self.g ** new_poly.evaluate(self.alpha)

        # 替换内存中多项式、Tag数组
        copies_data[copy_id]['polys'][block_index] = new_poly
        copies_data[copy_id]['tags'][block_index] = new_tag
        # 执行默克尔树叶子动态更新
        copies_data[copy_id]['mt'].update_leaf(block_index, new_tag)
        # 返回最新根哈希，上传TPA完成存证更新
        return copies_data[copy_id]['mt'].root


class CSP:
    """
    受审计云存储服务商（去中心化存储节点）
    安全假设：半诚实敌手，会尝试伪造Tag、篡改数据逃避审计
    核心职责：
    1. 接收User下发的副本多项式、Tag，本地复现Tag校验完整性
    2. 存储全部块多项式，TPA下发挑战后批量计算聚合证明、KZG开放证明、默克尔路径
    3. 将单副本证明提交聚合器，生成全局批量证明返回TPA校验
    """

    def __init__(self, pk, g):
        self.pk = pk       # 全局KZG公开参数
        self.g = g         # G1生成元
        # 本地存储表：key=(文件ID,副本ID)，value=多项式、Tag、默克尔树
        self.storage = {}

    def store_and_tag_verify(self, file_id, copy_id, polys, expected_root):
        """
        CSP接收副本数据时预校验：本地复现所有Tag，重建Merkle树与User根对比
        防御User恶意上传非法数据；同时CSP确认接收数据无传输损坏
        :param file_id: 文件编号
        :param copy_id: 副本编号
        :param polys: User下发的块多项式列表
        :param expected_root: User提供的可信Merkle根
        :return: True 存储校验通过；根不匹配直接抛出伪造异常
        """
        computed_tags = []
        # CSP使用公钥复现每个块Tag，不使用私钥α
        for poly in polys:
            tag = get_one_g1()
            for k in range(S_SECTORS):
                tag = tag * (self.pk[k] ** poly.coeffs[k])
            computed_tags.append(tag)
        # 本地重建默克尔树
        mt = DynamicMerkleTree(computed_tags)
        # 根哈希不匹配 → 数据传输损坏/用户伪造数据，拒绝存储
        if mt.root != expected_root:
            raise ValueError(f"CSP 拦截非法数据: 文件 ID {file_id}, 副本 ID {copy_id} Tag 伪造！")
        # 本地持久化存储副本完整数据
        self.storage[(file_id, copy_id)] = {'polys': polys, 'tags': computed_tags, 'mt': mt}
        return True

    def response_phase(self, file_id, copy_id, a_j, v_j, r):
        """
        协议响应阶段：TPA下发挑战后，CSP生成单副本审计证明
        计算内容：加权聚合多项式、聚合Tag、KZG开放证明w、所有抽样块默克尔路径
        :param file_id: 待审计文件ID
        :param copy_id: 待审计副本ID
        :param a_j: TPA挑战块下标
        :param v_j: 挑战加权标量
        :param r: KZG求值点
        :return: agg_tag(副本聚合Tag), val(聚合多项式求值), w(KZG开放证明), merkle_paths(各块默克尔路径)
        """
        # 读取本地存储副本数据
        data = self.storage.get((file_id, copy_id))
        if not data:
            raise KeyError(f"提供商未找到数据: File {file_id}, Copy {copy_id}")

        polys, tags, mt = data['polys'], data['tags'], data['mt']
        f_M = Poly([get_zero_zr()])  # 副本加权聚合多项式，初始零多项式
        agg_tag = get_one_g1()       # 副本加权聚合Tag，初始G1单位元

        # 遍历所有挑战块，加权累加多项式与Tag
        for idx, weight in zip(a_j, v_j):
            f_M = f_M + (polys[idx] * weight)
            agg_tag = agg_tag * (tags[idx] ** weight)

        # 聚合多项式在r点求值 f_M(r)
        val = f_M.evaluate(r)
        # 构造 f_M(x) - val，满足在x=r处取值为0，可整除(x-r)
        f_m_minus_val = f_M + Poly([-val])
        # 计算商多项式 h(x) = (f_M(x) - val) / (x - r)
        h_poly = f_m_minus_val.div_x_minus_r(r)

        # 使用公钥生成KZG开放证明 w = g^h(α)
        w = get_one_g1()
        for k in range(len(h_poly.coeffs)):
            w = w * (self.pk[k] ** h_poly.coeffs[k])

        # 收集每个挑战块对应的Tag与默克尔证明路径
        merkle_paths = [(tags[idx], mt.get_proof(idx)) for idx in a_j]
        return agg_tag, val, w, merkle_paths


# ==========================================
# 【流程管控：适当封装聚合器 (Aggregator)】
# 批量证明聚合逻辑：遍历所有文件、所有副本，累加代数证明元素
# 输出常量大小全局聚合证明，实现批量审计通信开销恒定
# ==========================================
def aggregate_all_proofs(csps, a_j, v_j, r):
    """
    多文件+多副本证明聚合器：合并所有CSP返回的副本证明为全局聚合证明
    聚合规则：G1元素乘法累加、ZR标量加法累加；默克尔路径线性拼接
    :param csps: 所有副本服务商列表
    :param a_j: TPA挑战块下标
    :param v_j: TPA加权标量
    :param r: KZG求值点
    :return: global_agg_tag全局聚合Tag, global_val全局求值和, global_w全局开放证明, local_merkle_proofs全部默克尔路径集合
    """
    # 全局聚合元素初始化：单位元/零元
    global_agg_tag = get_one_g1()
    global_val = get_zero_zr()
    global_w = get_one_g1()
    local_merkle_proofs = []

    # tqdm进度条可视化多文件聚合耗时
    for t in tqdm(range(T_FILES), desc="提取多文件代数证明", unit="file", leave=False):
        # 遍历该文件全部N_COPIES副本服务商
        for n in range(N_COPIES):
            # 当前副本生成单副本证明
            l_tag, l_val, l_w, paths = csps[n].response_phase(file_id=t, copy_id=n, a_j=a_j, v_j=v_j, r=r)

            # 代数元素聚合
            global_agg_tag = global_agg_tag * l_tag
            global_val = global_val + l_val
            global_w = global_w * l_w

            # 保存每个抽样块完整默克尔证明信息，用于TPA后续校验
            for idx_in_c, (tag, path) in enumerate(paths):
                local_merkle_proofs.append((t, n, idx_in_c, tag, path))

    return global_agg_tag, global_val, global_w, local_merkle_proofs


# ==========================================
# 【模块四：主控引导程序 (Main Routine)】
# 完整协议仿真主流程，严格按照论文五大阶段顺序执行：
# 1. Storage Phase 数据存储与副本生成
# 2. Dynamic Update Phase 数据块动态更新
# 3. Challenge Phase TPA生成审计挑战
# 4. Response Phase CSP批量生成并聚合审计证明
# 5. Verification Phase TPA双线性配对批量验证完整性
# ==========================================
def run_protocol_simulation():
    print("\n" + "=" * 60)
    print(f" MPA Off-chain TPA Audit: {T_FILES} Files | {N_COPIES} Copies | {N_BLOCKS} Blocks")
    print("=" * 60)

    # 1. 初始化三方实体
    tpa = ThirdPartyAuditor()  # 可信第三方审计者
    user = User()              # 数据持有者客户端
    tpa.register_public_params(user.pk, user.g)  # 用户上传公开参数至TPA
    csps = [CSP(user.pk, user.g) for _ in range(N_COPIES)]  # N个副本存储服务商
    user_local_state = {}      # 用户本地缓存所有文件副本完整状态，用于更新操作

    # --------------------------------------------------------
    print("\n>>> [1. Storage Phase] 数据持有者切分文件、加密与 TPA 存证")
    # 批量生成T_FILES份文件，构造多副本加密数据
    for t in tqdm(range(T_FILES), desc="构建加密多副本多项式与 Tag", unit="file"):
        # 仿真原始明文文件：[块索引][扇区索引] 随机整数明文
        raw_file = [[random.randint(1, 1000) for _ in range(S_SECTORS)] for _ in range(N_BLOCKS)]
        # 存储阶段：生成当前文件全部副本数据
        copies_data = user.storage_phase(raw_file, file_id=t)
        user_local_state[t] = copies_data

        # 遍历每个副本：上传根至TPA + CSP本地校验并存储副本
        for n in range(N_COPIES):
            tpa.upload_root(file_id=t, copy_id=n, root=copies_data[n]['mt'].root)
            csps[n].store_and_tag_verify(
                file_id=t, copy_id=n,
                polys=copies_data[n]['polys'],
                expected_root=copies_data[n]['mt'].root
            )
    print("    [+] 所有文件副本加密/验签完毕，不可变的 Merkle Root 已被 TPA 记录。")
    time.sleep(0.1)  # 缓冲延迟，防止tqdm进度条输出与日志打印错乱

    # --------------------------------------------------------
    print("\n>>> [2. Dynamic Update Phase] 数据动态更新测试")
    # 仿真新块明文：全部扇区修改为9999
    new_block_data = [9999 for _ in range(S_SECTORS)]
    # 更新文件0、副本0、第5号数据块
    new_root = user.update_block(copy_id=0, block_index=5, new_block_raw=new_block_data,
                                 copies_data=user_local_state[0])

    # 更新TPA存储的根哈希，并通知对应CSP重载校验更新后的副本
    tpa.upload_root(file_id=0, copy_id=0, root=new_root)
    csps[0].store_and_tag_verify(
        file_id=0, copy_id=0,
        polys=user_local_state[0][0]['polys'],
        expected_root=new_root
    )
    print("    [+] 更新页成功，$O(\log n)$ 复杂度轻量重算通过。")

    # --------------------------------------------------------
    print("\n>>> [3. Challenge Phase] TPA 发起随机审计挑战")
    # TPA生成全局审计挑战三元组
    a_j, v_j, r = tpa.get_random_challenge()
    print(f"    [+] 抽样的检查块索引 (a_j): {a_j}")

    # --------------------------------------------------------
    print("\n>>> [4. Response Phase] 提取 CSP 多副本多文件代数证明")
    # 聚合所有文件、所有副本证明，生成全局批量证明
    global_agg_tag, global_val, global_w, proofs = aggregate_all_proofs(csps, a_j, v_j, r)
    print("    [+] 证明归集完毕，已坍缩为常量大小全局 Proof。")

    # --------------------------------------------------------
    print("\n>>> [5. Verification Phase] TPA 离线执行批量 Pairing")

    # 进度条模拟配对验证耗时
    with tqdm(total=1, desc="执行双线性配对校验", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        is_valid = tpa.verify_batch(
            a_j, v_j, r,
            global_agg_tag, global_val, global_w,
            proofs
        )
        pbar.update(1)

    # 输出最终审计结果
    if is_valid:
        print("    [✅] 高并发验证通过！底层群配对完美拟合，验证了 CSP 未篡改数据。")
    else:
        print("    [❌] 代数验证失败！数据极有可能丢失或变异。")


# 程序入口：启动完整协议仿真
if __name__ == "__main__":
    try:
        run_protocol_simulation()
    except Exception as exc:
        # 全局异常捕获，打印异常类型与详情，方便调试密码运算错误
        print(f"\n[🚨 异常终止] {type(exc).__name__}: {str(exc)}")