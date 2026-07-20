// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface ISystemParam {
    function g2() external view returns (bytes memory);
    function pairingAddr() external view returns (address);
}

interface IRootStorage {
    function getRoot(uint256 fileId, uint256 copyId)
        external
        view
        returns (bytes32);
}

contract BatchAudit {
    // --- 常数 ---
    uint256 internal constant G1_LEN  = 128;
    uint256 internal constant G2_LEN  = 256;
    uint256 internal constant PAIR_LEN = 384; // G1 + G2

    // --- 不可变状态 ---
    address public immutable sysParam;
    address public immutable rootStorage;

    // --- 结构体 ---
    struct Proof {
        uint256   fileId;
        uint256   copyId;
        bytes     tagG1;       // 压缩 G1 点 (48B)
        uint256   leafIndex;   // 叶子位置
        bytes32[] siblings;    // Merkle 兄弟路径
        bool[]    isRight;     // 是否右兄弟
    }

    // --- 事件 ---
    event AuditVerified(bool passed, uint256 merkleChecks, uint256 gasUsed);
    event TamperDetected(uint256 gasUsed);

    // --- 构造函数 ---
    constructor(address _sysParam, address _rootStorage) {
        sysParam    = _sysParam;
        rootStorage = _rootStorage;
    }

    // ==============================================================
    //  核心批量验证
    // ==============================================================
    function verifyBatch(
        bytes    memory aG1,          // 128B: 全局聚合 A
        uint256          valGlobal,   // 全局聚合标量值
        bytes    memory wGlobal,      // 128B: 全局 KZG witness
        bytes    memory negWGlobal,   // 128B: -W_global
        bytes    memory cG2,          // 256B: C = pk_alpha (挑战多项式承诺)
        Proof[]  memory proofs        // Merkle 证明数组
    ) external {
        uint256 gasStart = gasleft();

        // 1. Merkle 路径校验
        for (uint256 i = 0; i < proofs.length; i++) {
            bool merkleOk = _checkMerkle(proofs[i]);
            require(merkleOk, "BatchAudit: Merkle check failed");
        }

        // 2. KZG 配对校验
        bool pairingOk = _checkPairing(aG1, negWGlobal, cG2);
        require(pairingOk, "BatchAudit: pairing check failed");

        uint256 gasUsed = gasStart - gasleft();
        emit AuditVerified(true, proofs.length, gasUsed);
    }

    // ==============================================================
    //  篡改测试 (期望配对失败 => 返回 true)
    // ==============================================================
    function verifyBatchMustFail(
        bytes    memory aG1,
        uint256          valGlobal,
        bytes    memory wGlobal,
        bytes    memory negWGlobal,
        bytes    memory cG2,
        Proof[]  memory proofs
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // Merkle 校验（同 verifyBatch 逻辑）
        for (uint256 i = 0; i < proofs.length; i++) {
            bool merkleOk = _checkMerkle(proofs[i]);
            if (!merkleOk) {
                emit TamperDetected(gasStart - gasleft());
                return true;
            }
        }

        // 配对校验：若通过（不应发生）→ false；若失败（预期）→ true
        bool pairingOk = _checkPairing(aG1, negWGlobal, cG2);
        if (pairingOk) {
            // 篡改未被检测到（不期望）
            return false;
        }

        emit TamperDetected(gasStart - gasleft());
        return true;
    }

    // ==============================================================
    //  内部: Merkle 校验
    // ==============================================================
    function _checkMerkle(Proof memory proof) private view returns (bool merkleOk) {
        // leaf = sha256(tagG1)  (tagG1 为 48 字节压缩 G1)
        bytes32 current = sha256(proof.tagG1);

        // 与链下 buildMerkleTree / verifyMerkleProof 完全一致:
        //   isRight[i] = true  => 当前节点是右孩子 => 兄弟在左 => sha256(sibling || current)
        //   isRight[i] = false => 当前节点是左孩子 => 兄弟在右 => sha256(current || sibling)
        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (proof.isRight[i]) {
                current = sha256(abi.encodePacked(proof.siblings[i], current));
            } else {
                current = sha256(abi.encodePacked(current, proof.siblings[i]));
            }
        }

        // 比对链上存证的 Root
        bytes32 expected = IRootStorage(rootStorage).getRoot(
            proof.fileId,
            proof.copyId
        );
        merkleOk = (current == expected);
    }

    // ==============================================================
    //  内部: KZG 配对校验 (BLS12-381, k=2 对)
    // ==============================================================
    function _checkPairing(
        bytes memory aG1,
        bytes memory negWGlobal,
        bytes memory cG2
    ) private view returns (bool) {
        address pairingAddr = ISystemParam(sysParam).pairingAddr();
        bytes   memory g2Bytes = ISystemParam(sysParam).g2();

        // 构造 pairingInput = aG1 || g2 || negWGlobal || cG2  (768B)
        bytes memory pairingInput = abi.encodePacked(aG1, g2Bytes, negWGlobal, cG2);
        require(pairingInput.length == 768, "BatchAudit: invalid pairing input length");

        // staticcall 到 EIP-2537 配对预编译 (0x0f) 或 shim
        (bool success, bytes memory result) = pairingAddr.staticcall(pairingInput);

        // EIP-2537 返回 32 字节，末字节为配对结果 (0x01 = 通过)
        return success
            && result.length >= 32
            && result[result.length - 1] == 0x01;
    }

    // ==============================================================
    //  Gas 估算 (EIP-2537)
    // ==============================================================
    function estimateCryptoGas(uint256 msmCount) external pure returns (uint256) {
        // EIP-2537 配对 Gas: 32600 * k + 37700 (k=2 对本协议)
        uint256 pairingGas = 32600 * 2 + 37700;
        // EIP-2537 MSM Gas: ~20650 * size + 85500
        uint256 msmGas = msmCount * 20650 + 85500;
        return pairingGas + msmGas + 50000; // 合约开销
    }
}
