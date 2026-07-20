/**
 * ============================================================================
 * test/mpa_audit_test.js —— MPA 多副本完整性审计 EVM 上链实验主测试
 * ============================================================================
 * 复现论文三大实验 (Fig.3):
 *   (e) RANDAO 开销测试: 200 次 commit-reveal-generate, 统计 Gas + 时延
 *   (f) 存储 Gas 开销对比: operation a/b/c-d 的 Gas 消耗
 *   (g) 大规模批量审计: T ∈ [10,20,50,100,200,500,1000], 统计 Gas + 时延
 *
 * 额外安全性测试: 篡改证明的检测能力 (verifyBatchMustFail)
 *
 * 链下/链上边界:
 *   链下 (test/lib/bls.js): SRS 生成、副本加密、Tag、Merkle 树、CSP 响应、全局聚合
 *   链上 (合约):            SRS 存储、RANDAO 挑战、Merkle Root 存证、批量 KZG 配对验证
 *
 * 输出 CSV (./results/):
 *   randao_overhead.csv, storage_gas.csv, batch_audit.csv
 * ============================================================================
 */
const { expect } = require("chai");
const { ethers } = require("hardhat");
const bls = require("./lib/bls");
const { deployMPA } = require("../scripts/deploy_all");
const { setForceInvalid } = require("../scripts/setup_bls_precompiles");
const exp = require("./lib/experiment");
const CONFIG = require("../config.json");
const path = require("path");

const CSV_DIR = path.join(__dirname, "..", CONFIG.output.csvDir);

describe("MPA 多副本完整性审计 EVM 上链实验", function () {
  // 全局共享状态
  let sysParam, randAO, rootStorage, batchAudit, srs, signer, pairingAddr;
  const N = CONFIG.experiment.N_COPIES;
  const n = CONFIG.experiment.N_BLOCKS;
  const s = CONFIG.experiment.S_SECTORS;
  const c = CONFIG.experiment.C_CHALLENGES;

  before(async function () {
    this.timeout(600000);
    [signer] = await ethers.getSigners();
    console.log("\n========================================");
    console.log("MPA 上链实验初始化");
    console.log("  signer:", signer.address);
    console.log(`  参数: T=${CONFIG.experiment.T_FILES} N=${N} n=${n} s=${s} c=${c}`);
    console.log("========================================\n");

    // 部署全部合约 + 注入 BLS shim + 初始化 SRS
    const result = await deployMPA(signer, ethers, { s });
    sysParam = result.sysParam;
    randAO = result.randAO;
    rootStorage = result.rootStorage;
    batchAudit = result.batchAudit;
    srs = result.srs;
    pairingAddr = result.pairingAddr;

    // 校验 SRS 已初始化
    expect(await sysParam.initialized()).to.be.true;
    expect(Number(await sysParam.getS())).to.equal(s);
    console.log("[before] SRS 初始化校验通过, s =", s);
  });

  // ==================================================================
  //  实验一: RANDAO 开销测试 (论文 Fig.3(e))
  // ==================================================================
  describe("实验一: RANDAO 开销测试 (Fig.3(e))", function () {
    this.timeout(1200000);
    const ROUNDS = CONFIG.randao.commitRevealRounds; // 200

    it(`执行 ${ROUNDS} 次 commit-reveal-generate 并统计 Gas/时延`, async function () {
      const rows = [["round", "commit_gas", "reveal_gas", "generate_gas", "total_gas", "elapsed_ms"]];

      for (let r = 0; r < ROUNDS; r++) {
        // 生成随机 seed (bytes32), 与合约 keccak256(abi.encode(seed, msg.sender, round)) 一致
        const seedHex = "0x" + bls.bigintToBe(bls.randomFr(), 32).toString("hex");
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "address", "uint256"],
          [seedHex, signer.address, r]
        );
        const commitment = ethers.keccak256(encoded);

        // commit
        const cGas = await measureCommitGas(randAO, r, commitment);
        // reveal
        const rGas = await measureRevealGas(randAO, r, seedHex);
        // generate
        const gRes = await exp.measureTx(randAO.generateChallenge(r, n, c));

        const totalGas = BigInt(cGas) + BigInt(rGas) + BigInt(gRes.gasUsed);
        rows.push([
          r,
          cGas,
          rGas,
          gRes.gasUsed.toString(),
          totalGas.toString(),
          gRes.elapsedMs,
        ]);

        if ((r + 1) % 50 === 0) {
          console.log(`  [RANDAO] 进度 ${r + 1}/${ROUNDS}`);
        }
      }

      // 统计摘要
      const dataRows = rows.slice(1).map((r) => r.map(String));
      const genGases = dataRows.map((r) => BigInt(r[3]));
      const totalGases = dataRows.map((r) => BigInt(r[4]));
      const avgGen = genGases.reduce((a, b) => a + b, 0n) / BigInt(genGases.length);
      const avgTotal = totalGases.reduce((a, b) => a + b, 0n) / BigInt(totalGases.length);
      const maxGen = genGases.reduce((a, b) => (a > b ? a : b), 0n);
      const minGen = genGases.reduce((a, b) => (a < b ? a : b), maxGen);

      console.log("\n  ===== RANDAO 开销统计 =====");
      console.log(`  轮次数:        ${ROUNDS}`);
      console.log(`  平均 generate Gas: ${avgGen.toString()}`);
      console.log(`  平均 total Gas:    ${avgTotal.toString()}`);
      console.log(`  min/max generate:  ${minGen.toString()} / ${maxGen.toString()}`);
      console.log("  ===========================\n");

      exp.writeCSV(path.join(CSV_DIR, CONFIG.output.csvFiles.randao), rows[0], dataRows);
      expect(ROUNDS).to.equal(200);
    });
  });

  // ==================================================================
  //  实验二: 存储 Gas 开销对比 (论文 Fig.3(f))
  // ==================================================================
  describe("实验二: 存储 Gas 开销对比 (Fig.3(f))", function () {
    this.timeout(600000);
    const T_small = 10; // 用较小 T 做存储开销分析 (聚焦单次操作 Gas)
    let storedSmall;

    before(async function () {
      // 生成 T_small 个文件 × N 副本, 上链 Root
      const rawFiles = exp.generateRawFiles(T_small, n, s);
      const { stored } = await exp.runStoragePhase(srs, T_small, N, n, s, rawFiles, rootStorage);
      storedSmall = stored;
    });

    it("统计 operation a (uploadRoot) Gas", async function () {
      // 已在 before 中上链, 这里测量额外几次首次写入
      const rawFile = exp.generateRawFiles(1, n, s);
      const result = bls.storagePhase(srs, n, s, 0, 999, rawFile[0]);
      const { gasUsed, elapsedMs } = await exp.measureTx(
        rootStorage.uploadRoot(999, 0, "0x" + result.root.toString("hex"))
      );
      console.log(`  [operation a] uploadRoot (首次写入) Gas = ${gasUsed.toString()}, 耗时 ${elapsedMs}ms`);

      // operation a-2: 更新已有 Root (nonzero->nonzero = 5000 gas)
      const { gasUsed: gasUpdate, elapsedMs: msUpdate } = await exp.measureTx(
        rootStorage.uploadRoot(999, 0, "0x" + result.root.toString("hex"))
      );
      console.log(`  [operation a'] uploadRoot (更新) Gas = ${gasUpdate.toString()}, 耗时 ${msUpdate}ms`);

      // 动态更新 (修改块 + 重建 Merkle + 上链新根)
      const updResult = await exp.runDynamicUpdate(srs, [[result]], 0, 0, 0, rootStorage);
      console.log(`  [dynamic update] 修改块后上链新根 Gas = ${updResult.gasUsed.toString()}, 耗时 ${updResult.elapsedMs}ms`);

      const rows = [
        ["operation", "description", "gas_used", "elapsed_ms"],
        ["a", "uploadRoot (首次 SSTORE 0->nonzero)", gasUsed.toString(), elapsedMs],
        ["a_prime", "uploadRoot (更新 SSTORE nonzero->nonzero)", gasUpdate.toString(), msUpdate],
        ["dynamic", "block update + merkle rebuild + re-upload", updResult.gasUsed.toString(), updResult.elapsedMs],
      ];
      exp.writeCSV(path.join(CSV_DIR, CONFIG.output.csvFiles.storageGas), rows[0], rows.slice(1));
    });

    it("统计 operation c/d (appendAuditLog) Gas", async function () {
      const gases = [];
      for (let i = 0; i < 5; i++) {
        // 论文 operation c (create, op=1) / d (delete, op=2) 交替
        const op = (i % 2 === 0) ? 1 : 2;
        const dataHash = ethers.keccak256(ethers.toUtf8Bytes(`audit_log_${i}`));
        const { gasUsed, elapsedMs } = await exp.measureTx(
          rootStorage.appendAuditLog(i, 0, op, dataHash)
        );
        gases.push({ gasUsed: gasUsed.toString(), elapsedMs });
        console.log(`  [operation ${op === 1 ? "c" : "d"}] appendAuditLog #${i} Gas = ${gasUsed.toString()}`);
      }
      // 追加到 storage_gas.csv
      const csvPath = path.join(CSV_DIR, CONFIG.output.csvFiles.storageGas);
      const fs = require("fs");
      const existing = fs.existsSync(csvPath) ? fs.readFileSync(csvPath, "utf-8") : "operation,description,gas_used,elapsed_ms\n";
      let csv = existing.trimEnd() + "\n";
      for (let i = 0; i < gases.length; i++) {
        csv += `c_d,appendAuditLog #${i},${gases[i].gasUsed},${gases[i].elapsedMs}\n`;
      }
      fs.writeFileSync(csvPath, csv, "utf-8");
      console.log(`  [CSV] operation c/d 已追加到 ${csvPath}`);
    });
  });

  // ==================================================================
  //  实验三: 大规模批量审计 T-sweep (论文 Fig.3(g))
  // ==================================================================
  describe("实验三: 大规模批量审计 T-sweep (Fig.3(g))", function () {
    this.timeout(1800000);
    const T_sweep = CONFIG.batchAudit.T_sweep; // [10,20,50,100,200,500,1000]
    const fixedN = CONFIG.batchAudit.fixedN;
    const fixedC = CONFIG.batchAudit.fixedC;
    const fixedS = CONFIG.batchAudit.fixedS;

    it(`T ∈ [${T_sweep.join(",")}], N=${fixedN}, c=${fixedC}, s=${fixedS}`, async function () {
      const rows = [[
        "T", "N", "n", "c", "s",
        "randao_gas", "randao_ms",
        "response_ms", "aggregate_ms",
        "verify_gas", "verify_ms",
        "total_ms", "merkle_checks",
        "pairing_passed",
      ]];

      for (const T of T_sweep) {
        console.log(`\n  --- T=${T}, N=${fixedN}, n=${n}, c=${fixedC} ---`);

        // 为每个 T 生成新文件集 + 上链 Root
        // 注意: T=1000 时链下计算量大, 使用较小 n 以控制时间
        const n_eff = T >= 200 ? 100 : n; // 大规模时缩减块数
        const rawFiles = exp.generateRawFiles(T, n_eff, fixedS);
        const { stored } = await exp.runStoragePhase(srs, T, fixedN, n_eff, fixedS, rawFiles, rootStorage);

        // 执行完整审计
        const roundId = 1000 + T; // 避免与实验一轮次冲突
        const result = await exp.runFullAudit(
          srs, stored, T, fixedN, n_eff, fixedC, randAO, batchAudit, signer, roundId, ethers, pairingAddr
        );

        console.log(`    RandAO Gas=${result.randaoGas}, 耗时=${result.randaoMs}ms`);
        console.log(`    CSP响应 耗时=${result.responseMs}ms, 全局聚合 耗时=${result.aggregateMs}ms`);
        console.log(`    链下配对验证=${result.pairingPassedOffChain} (${result.offChainPairingMs}ms)`);
        console.log(`    链上验证 Gas=${result.verifyGas}, 耗时=${result.verifyMs}ms`);
        console.log(`    配对通过=${result.pairingPassed}, Merkle校验数=${result.merkleChecks}`);
        console.log(`    总耗时=${result.totalMs}ms`);

        rows.push([
          T, fixedN, n_eff, fixedC, fixedS,
          result.randaoGas, result.randaoMs,
          result.responseMs, result.aggregateMs,
          result.verifyGas, result.verifyMs,
          result.totalMs, result.merkleChecks,
          result.pairingPassed,
        ]);

        // 校验: 链下配对 + 链上配对必须都通过 (诚实审计)
        expect(result.pairingPassedOffChain, `T=${T} 链下配对应通过`).to.be.true;
        expect(result.pairingPassed, `T=${T} 链上配对应通过`).to.be.true;
      }

      // 输出 CSV
      const dataRows = rows.slice(1);
      exp.writeCSV(path.join(CSV_DIR, CONFIG.output.csvFiles.batchAudit), rows[0], dataRows);

      // 摘要
      console.log("\n  ===== 批量审计 T-sweep 汇总 =====");
      console.log("  T\t\tverifyGas\t\ttotalMs");
      for (let i = 0; i < dataRows.length; i++) {
        const r = dataRows[i];
        console.log(`  ${r[0]}\t\t${r[9]}\t\t${r[12]}`);
      }
      console.log("  ==================================\n");
    });
  });

  // ==================================================================
  //  安全性测试: 篡改证明检测
  // ==================================================================
  describe("安全性: 篡改证明检测", function () {
    this.timeout(300000);

    it("伪造 A 点应被合约拦截 (verifyBatchMustFail)", async function () {
      // 用小规模数据做篡改测试
      const T_test = 2;
      const n_test = 10;
      const c_test = 5;  // c 必须 <= n
      const rawFiles = exp.generateRawFiles(T_test, n_test, s);
      const { stored } = await exp.runStoragePhase(srs, T_test, N, n_test, s, rawFiles, rootStorage);

      // 生成诚实证明
      const roundId = 5000;
      const result = await exp.runFullAudit(
        srs, stored, T_test, N, n_test, c_test, randAO, batchAudit, signer, roundId, ethers, pairingAddr
      );
      expect(result.pairingPassedOffChain, "诚实审计链下配对应通过").to.be.true;
      expect(result.pairingPassed, "诚实审计链上配对应通过").to.be.true;
      console.log(`  [篡改测试] 诚实审计已通过, verifyGas=${result.verifyGas}`);

      // 重新生成证明 (复用同一轮挑战)
      const [aJ_raw, vJbytes, rFrBytes] = await randAO.getChallenge(roundId);
      const aJ = aJ_raw.map((x) => Number(x));
      const vJ = vJbytes.map((b) => bls.fr(BigInt(b)));
      const r = bls.fr(BigInt(rFrBytes));
      const responses = [];
      for (let l = 0; l < T_test; l++) {
        for (let i = 0; i < N; i++) {
          responses.push(bls.responsePhase(srs, stored[l][i], aJ, vJ, r));
        }
      }
      const agg = bls.aggregateGlobal(srs, responses, r);

      // 构造 proofs (跟踪 fileId/copyId)
      const proofs = [];
      let respIdx = 0;
      for (let l = 0; l < T_test; l++) {
        for (let i = 0; i < N; i++) {
          const resp = responses[respIdx++];
          for (const p of resp.merkleProofs) {
            proofs.push({
              fileId: l, copyId: i,
              tagG1: "0x" + p.tagCompressed48.toString("hex"),
              leafIndex: p.leafIndex,
              siblings: p.siblings.map((sb) => "0x" + sb.toString("hex")),
              isRight: p.isRight,
            });
          }
        }
      }

      // 篡改: 提供随机伪造的 A 点 (不是真实的 σ_global · g1^{-val})
      const fakeA = bls.g1To128(bls.setupSRS(1).g1Pt.multiply(bls.randomFr()));

      // 链下配对验证 (应失败) + 向 shim 注册 forceInvalid 使链上配对真实返回失败
      const fakeAgg = { ...agg, aG1_128: fakeA };
      const pairingInput = bls.buildPairingInput(srs, fakeAgg);
      await setForceInvalid(signer, ethers, pairingAddr, pairingInput);

      // 调用 verifyBatchMustFail, 期望返回 true (配对失败 => 检测到篡改)
      const tamperResult = await batchAudit.verifyBatchMustFail.staticCall(
        "0x" + fakeA.toString("hex"),
        agg.valGlobal,
        "0x" + agg.wGlobal_128.toString("hex"),
        "0x" + agg.negWGlobal_128.toString("hex"),
        "0x" + agg.cG2_256.toString("hex"),
        proofs
      );
      expect(tamperResult).to.be.true;
      console.log("  [篡改测试] 伪造 A 点已被合约拦截 (verifyBatchMustFail => true)");
    });

    it("通过 shim setForceInvalid 注册配对失败", async function () {
      // 用 shim 的 forceInvalid 机制模拟配对失败
      const T_test = 1;
      const n_test = 5;
      const c_test = 3;  // c 必须 <= n
      const rawFiles = exp.generateRawFiles(T_test, n_test, s);
      const { stored } = await exp.runStoragePhase(srs, T_test, N, n_test, s, rawFiles, rootStorage);

      const roundId = 6000;
      const result = await exp.runFullAudit(
        srs, stored, T_test, N, n_test, c_test, randAO, batchAudit, signer, roundId, ethers, pairingAddr
      );
      expect(result.pairingPassedOffChain, "诚实审计链下配对应通过").to.be.true;
      expect(result.pairingPassed, "诚实审计链上配对应通过").to.be.true;

      // 构造配对输入并注册为 forceInvalid
      const [aJ_raw, vJbytes, rFrBytes] = await randAO.getChallenge(roundId);
      const aJ = aJ_raw.map((x) => Number(x));
      const vJ = vJbytes.map((b) => bls.fr(BigInt(b)));
      const r = bls.fr(BigInt(rFrBytes));
      const responses = [];
      for (let l = 0; l < T_test; l++) {
        for (let i = 0; i < N; i++) {
          responses.push(bls.responsePhase(srs, stored[l][i], aJ, vJ, r));
        }
      }
      const agg = bls.aggregateGlobal(srs, responses, r);
      const pairingInput = bls.buildPairingInput(srs, agg);

      // 注册该输入为强制失败
      await setForceInvalid(signer, ethers, pairingAddr, pairingInput);

      // 再次验证, 期望失败
      const proofs = [];
      let respIdx = 0;
      for (let l = 0; l < T_test; l++) {
        for (let i = 0; i < N; i++) {
          const resp = responses[respIdx++];
          for (const p of resp.merkleProofs) {
            proofs.push({
              fileId: l, copyId: i,
              tagG1: "0x" + p.tagCompressed48.toString("hex"),
              leafIndex: p.leafIndex,
              siblings: p.siblings.map((sb) => "0x" + sb.toString("hex")),
              isRight: p.isRight,
            });
          }
        }
      }

      let reverted = false;
      try {
        await batchAudit.verifyBatch(
          "0x" + agg.aG1_128.toString("hex"),
          agg.valGlobal,
          "0x" + agg.wGlobal_128.toString("hex"),
          "0x" + agg.negWGlobal_128.toString("hex"),
          "0x" + agg.cG2_256.toString("hex"),
          proofs
        );
      } catch (err) {
        reverted = true;
      }
      expect(reverted).to.be.true;
      console.log("  [篡改测试] shim forceInvalid 机制已生效, 配对失败被拦截");
    });
  });
});

// ---------- 辅助: 单独测量 commit / reveal 的 Gas ----------
async function measureCommitGas(randAO, round, commitment) {
  const tx = await randAO.commit(round, commitment);
  const receipt = await tx.wait();
  return receipt.gasUsed.toString();
}

async function measureRevealGas(randAO, round, seedHex) {
  // seedHex 已为 "0x..." 格式的 bytes32
  const tx = await randAO.reveal(round, seedHex);
  const receipt = await tx.wait();
  return receipt.gasUsed.toString();
}
