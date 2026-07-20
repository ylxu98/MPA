// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract FileRootStorage {
    // --- 事件 ---
    event RootUploaded(uint256 indexed fileId, uint256 indexed copyId, bytes32 root);
    event AuditLogAppended(
        uint256 indexed fileId,
        uint256 indexed copyId,
        uint8   operation,
        bytes32 dataHash
    );

    // --- 状态变量 ---
    address public immutable owner;
    uint256 public totalRootWrites;

    // 内部 mapping: roots[fileId][copyId] => Merkle Root
    mapping(uint256 => mapping(uint256 => bytes32)) private roots;

    // --- 修饰器 ---
    modifier onlyOwner() {
        require(msg.sender == owner, "FileRootStorage: caller is not owner");
        _;
    }

    // --- 构造函数 ---
    constructor() {
        owner = msg.sender;
    }

    // 上传 / 更新 Merkle Root (operation a)
    function uploadRoot(
        uint256 fileId,
        uint256 copyId,
        bytes32 root
    ) external onlyOwner {
        roots[fileId][copyId] = root;
        totalRootWrites++;
        emit RootUploaded(fileId, copyId, root);
    }

    // 查询已存证的 Merkle Root
    function getRoot(uint256 fileId, uint256 copyId)
        external
        view
        returns (bytes32)
    {
        return roots[fileId][copyId];
    }

    // 追加审计日志 (operation c/d)
    // operation: 1=create, 2=delete (按论文 operation c/d)
    function appendAuditLog(
        uint256 fileId,
        uint256 copyId,
        uint8   operation,
        bytes32 dataHash
    ) external onlyOwner {
        emit AuditLogAppended(fileId, copyId, operation, dataHash);
    }
}
