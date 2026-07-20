// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// BLSPairingShim: 模拟 BLS12-381 EIP-2537 预编译
// 用于 Hardhat 网络在 0x0b~0x0f 无原生 BLS 支持的场景
// 运行时字节码由 setup_bls_precompiles.js 注入到预编译地址
//
// 关键: admin 必须是 slot 0, 供 hardhat_setStorageAt 直接写入

contract BLSPairingShim {
    // --- EIP-2537 预编译地址常量 ---
    address internal constant PRECOMPILE_G1ADD   = address(0x0b);
    address internal constant PRECOMPILE_G1MSM   = address(0x0c);
    address internal constant PRECOMPILE_G2ADD   = address(0x0d);
    address internal constant PRECOMPILE_G2MSM   = address(0x0e);
    address internal constant PRECOMPILE_PAIRING = address(0x0f);

    // 单对输入/输出长度
    uint256 internal constant G1_LEN  = 128;
    uint256 internal constant G2_LEN  = 256;
    uint256 internal constant PAIR_LEN = 384;

    // --- 状态变量 (admin 必须在 slot 0) ---
    address public admin;

    // oracle 映射: 注册特定输入的预期输出 (正例 / 负例)
    mapping(bytes32 => bytes)  public expectedOutput;
    mapping(bytes32 => bool)   public forceInvalid;

    // --- 修饰器 ---
    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    // --- 构造函数 ---
    constructor() {
        admin = msg.sender;
    }

    // 注册预期配对输出
    function setExpected(bytes32 key, bytes memory output) external onlyAdmin {
        expectedOutput[key] = output;
    }

    // 强制某输入返回配对失败 (0x00 末字节)
    function setForceInvalid(bytes32 key, bool flag) external onlyAdmin {
        forceInvalid[key] = flag;
    }

    // fallback: 兼容 EIP-2537 预编译接口
    fallback(bytes calldata input) external returns (bytes memory) {
        // 按 EIP-2537 Gas 公式烧 Gas: 32600 * k + 37700
        // k = input.length / 384 (配对对数)
        uint256 k = input.length / PAIR_LEN;
        uint256 gasCost = 32600 * k + 37700;

        // 通过循环消耗 Gas
        uint256 gasStart = gasleft();
        while (gasStart - gasleft() < gasCost) {
            // 空循环 - 仅消耗 Gas
        }

        // 计算 inputHash = keccak256(abi.encodePacked(address(this), input))
        bytes32 inputHash = keccak256(abi.encodePacked(address(this), input));

        // 1. 强制无效 (篡改测试)
        if (forceInvalid[inputHash]) {
            return abi.encodePacked(
                uint256(0x0000000000000000000000000000000000000000000000000000000000000000)
            );
        }

        // 2. 已注册的预期输出
        bytes memory stored = expectedOutput[inputHash];
        if (stored.length > 0) {
            return stored;
        }

        // 3. 默认: 配对通过, 返回 32 字节末尾 0x01
        return abi.encodePacked(
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001)
        );
    }
}
