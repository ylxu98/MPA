// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// EIP-2537 (BLS12-381) precompile addresses
// 使用 address(0x0b) 格式以避免 checksum 问题

contract SystemParam {
    // --- 常量 ---
    // BLS12-381 标量域阶 r
    uint256 public constant BLS_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // EIP-2537 预编译地址
    address internal constant PRECOMPILE_G1ADD   = address(0x0b);
    address internal constant PRECOMPILE_G1MSM   = address(0x0c);
    address internal constant PRECOMPILE_G2ADD   = address(0x0d);
    address internal constant PRECOMPILE_G2MSM   = address(0x0e);
    address internal constant PRECOMPILE_PAIRING = address(0x0f);

    // --- 状态变量 ---
    address public immutable owner;
    bool    public initialized;
    bytes   public g1;       // G1 生成元 (128B 压缩)
    bytes   public g2;       // G2 生成元 (256B 压缩)
    bytes[] public pkG1;     // SRS G1 幂数组 [g1^{α^i}] (各 128B)
    bytes   public g2Alpha;  // [g2]^α (256B)
    address public pairingAddr;

    // --- 修饰器 ---
    modifier onlyOwner() {
        require(msg.sender == owner, "SystemParam: caller is not owner");
        _;
    }

    // --- 构造函数 ---
    constructor() {
        owner       = msg.sender;
        initialized = false;
    }

    // 链上 SRS 初始化（仅一次）
    function initialize(
        bytes   memory _g1,
        bytes   memory _g2,
        bytes[] memory _pkG1,
        bytes   memory _g2Alpha,
        address _pairingAddr
    ) external onlyOwner {
        require(!initialized, "SystemParam: already initialized");
        g1          = _g1;
        g2          = _g2;
        pkG1        = _pkG1;
        g2Alpha     = _g2Alpha;
        pairingAddr = _pairingAddr;
        initialized = true;
    }

    // 更新配对预编译地址（后续升级用）
    function setPairingAddr(address _addr) external onlyOwner {
        pairingAddr = _addr;
    }

    // 返回 SRS 扇区数 s = |pkG1|
    function getS() external view returns (uint256) {
        return pkG1.length;
    }

    // 将 uint256 归约到 BLS12-381 标量域 Fr (mod r)
    function reduceFr(uint256 x) public pure returns (uint256) {
        return x % BLS_SCALAR_R;
    }
}
