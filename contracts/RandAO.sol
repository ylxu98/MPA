// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract RandAO {
    // BLS12-381 标量域阶 r
    uint256 public constant BLS_SCALAR_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // --- 结构体 ---
    struct Round {
        mapping(address => bytes32) commitments;
        address[]                   committers;
        mapping(address => bytes32) revealedSeeds;
        mapping(address => bool)    hasRevealed;
        uint256                     revealedCount;
        uint256[]                   aJ;         // 挑战块索引
        bytes32[]                   vJ;         // 挑战系数 (归约到 Fr)
        bytes32                     rFr;        // 全局随机标量 (归约到 Fr)
        bool                        generated;  // 是否已生成
    }

    mapping(uint256 => Round) private rounds;

    // --- 事件 ---
    event Committed(uint256 indexed round, address indexed sender, bytes32 commitment);
    event Revealed(uint256 indexed round, address indexed sender, bytes32 seed);
    event ChallengeGenerated(
        uint256   indexed round,
        uint256[] aJ,
        bytes32[] vJ,
        bytes32   rFr
    );

    // --- 构造函数 ---
    constructor() {}

    // 提交种子承诺
    function commit(uint256 round, bytes32 commitment) public {
        Round storage rnd = rounds[round];
        require(!rnd.generated, "RandAO: round already generated");
        rnd.commitments[msg.sender] = commitment;
        rnd.committers.push(msg.sender);
        emit Committed(round, msg.sender, commitment);
    }

    // 揭晓种子，校验承诺一致性
    function reveal(uint256 round, bytes32 seed) public {
        Round storage rnd = rounds[round];
        require(!rnd.generated, "RandAO: round already generated");
        require(!rnd.hasRevealed[msg.sender], "RandAO: already revealed");

        bytes32 expected = keccak256(abi.encode(seed, msg.sender, round));
        require(rnd.commitments[msg.sender] == expected, "RandAO: commitment mismatch");

        rnd.revealedSeeds[msg.sender] = seed;
        rnd.hasRevealed[msg.sender]   = true;
        rnd.revealedCount++;
        emit Revealed(round, msg.sender, seed);
    }

    // 聚合揭晓种子，派生审计三元组 (a_j, v_j, r)
    function generateChallenge(uint256 round, uint256 n, uint256 c)
        public
        returns (uint256[] memory aJ, bytes32[] memory vJ, bytes32 rFr)
    {
        Round storage rnd = rounds[round];
        require(!rnd.generated, "RandAO: already generated");
        require(rnd.revealedCount > 0, "RandAO: no reveals");
        require(c <= n, "RandAO: c > n");

        // 聚合所有揭晓种子 => masterSeed
        bytes32 masterSeed;
        {
            address[] storage committers = rnd.committers;
            // 逐地址迭代，仅取已揭晓者的种子
            for (uint256 i = 0; i < committers.length; i++) {
                address addr = committers[i];
                if (rnd.hasRevealed[addr]) {
                    masterSeed = keccak256(
                        abi.encodePacked(masterSeed, rnd.revealedSeeds[addr])
                    );
                }
            }
        }

        // Fisher-Yates 无放回采样 c 个索引
        aJ = new uint256[](c);
        uint256[] memory pool = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pool[i] = i;
        }
        for (uint256 i = 0; i < c; i++) {
            uint256 rand = uint256(
                keccak256(abi.encodePacked(masterSeed, "a", i))
            );
            uint256 j = i + (rand % (n - i));
            // swap pool[i] <-> pool[j]
            uint256 tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
            aJ[i] = pool[i];
        }

        // v_j: 每个挑战块的随机系数，归约到 Fr
        vJ = new bytes32[](c);
        for (uint256 i = 0; i < c; i++) {
            uint256 v = uint256(
                keccak256(abi.encodePacked(masterSeed, "v", i))
            ) % BLS_SCALAR_R;
            vJ[i] = bytes32(v);
        }

        // r: 全局随机标量，归约到 Fr
        uint256 rVal = uint256(
            keccak256(abi.encodePacked(masterSeed, "r"))
        ) % BLS_SCALAR_R;
        rFr = bytes32(rVal);

        // 写入存储
        rnd.aJ        = aJ;
        rnd.vJ        = vJ;
        rnd.rFr       = rFr;
        rnd.generated = true;

        emit ChallengeGenerated(round, aJ, vJ, rFr);
    }

    // 便捷接口: 单笔交易内完成 commit + reveal + generate
    function singleShotGenerate(
        uint256 round,
        bytes32 seed,
        uint256 n,
        uint256 c
    ) external {
        bytes32 commitment = keccak256(abi.encode(seed, msg.sender, round));
        commit(round, commitment);
        reveal(round, seed);
        generateChallenge(round, n, c);
    }

    // 查询已生成的挑战三元组
    function getChallenge(uint256 round)
        external
        view
        returns (
            uint256[] memory aJ,
            bytes32[] memory vJ,
            bytes32 rFr
        )
    {
        Round storage rnd = rounds[round];
        require(rnd.generated, "RandAO: not generated");
        return (rnd.aJ, rnd.vJ, rnd.rFr);
    }
}
