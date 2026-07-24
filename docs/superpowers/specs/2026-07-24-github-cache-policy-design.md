# GitHub Actions 缓存策略设计

## 背景

当前仓库的 Actions 缓存把 Cargo registry、Cargo git checkout 和各目标的
`target` 放在同一个缓存中。release 矩阵因此重复保存依赖；旧锁文件和旧版本
又留下了大量不可复用的缓存。当前仓库共有约 13.94 GB 缓存，超过 GitHub 默认
的 10 GB 仓库缓存上限。

工作流固定使用 Rust `1.91.1`，而 GitHub Ubuntu runner 预装的 Rust 版本不一定
相同，因此每个 job 仍会产生固定版本 toolchain 的安装开销。toolchain 可以缓存，
但必须作为所有 Ubuntu x86_64 job 共享的一份缓存，不能按交叉编译目标复制。

## 目标

1. 删除不再被新工作流使用的旧版本和旧锁文件缓存。
2. 让 CI 和 release 矩阵共享 Cargo 依赖缓存。
3. 让所有 job 共享一份固定 Rust toolchain 缓存。
4. 让每个 release 目标只保存自己的 `target` 缓存。
5. 让 `cross` 按版本单独缓存，避免每个矩阵 job 重复安装。
6. 不缓存 apt/ripgrep 和完整 runner 镜像内容，避免低收益缓存膨胀。
7. 通过 GitHub Actions 实际运行和缓存 API 统计确认最终占用。

## 设计

### 缓存层次

缓存键使用 runner OS、runner 架构、Rust 版本、工具版本和 `Cargo.lock` 哈希
区分不同内容：

- **Rust toolchain cache**：`~/.rustup/toolchains/1.91.1-*`，所有 Ubuntu
  x86_64 job 共用，键包含 Rust 版本和最小 profile。
- **Cargo dependency cache**：`~/.cargo/registry` 与 `~/.cargo/git`，CI、
  bridge release 和 helper release 共用，键包含 Rust 版本和锁文件哈希。
- **Target cache**：仅 `target`，CI 使用一个共享键；release 使用
  `bridge/helper + target triple` 的独立键。
- **cross cache**：`~/.cargo/bin/cross`，键包含 Rust 版本和 `cross` 版本，
  所有 release job 共用。

新键不再兼容旧的组合缓存，因此旧组合缓存应在新工作流推送后清理。

### Toolchain 恢复顺序

每个 job 先恢复 Rust toolchain cache，再执行固定版本的
`rustup toolchain install --profile minimal`。缓存命中时该命令只做快速存在性
确认；未命中时正常下载并由 `actions/cache` 的 post step 保存。quality job
继续显式添加 rustfmt 和 clippy，保证缓存不改变工具链组件的正确性。

### cross 恢复顺序

release job 先恢复 cross cache；只有缓存未命中时才执行固定版本的
`cargo install cross --locked`，随后验证 `$HOME/.cargo/bin/cross` 可执行并输出
版本。这样即使多个矩阵 job 首次并发，最多只有首次缓存填充产生安装开销。

### 清理策略

旧键包括此前的 `Linux-rust-*`, `bridge-*` 和 `helper-*` 组合缓存，以及旧
`Cargo.lock` 哈希对应的版本缓存。它们不被新键读取，统一删除；新工作流首次
运行后只保留新的四类缓存。

## 不在范围内

- 不缓存 `apt` 包或 `ripgrep`，因为 Ubuntu runner 已包含大多数常用工具，且
  apt 缓存无法跨 runner 镜像稳定复用。
- 不缓存整个 `~/.rustup`，避免把更新元数据、临时文件和其他默认 toolchain
  一起带入缓存。
- 不改变 release artifact 的保留期和发布逻辑。

## 验证标准

1. GitHub Actions quality、diagnostics、build-main 和 build-helper 均成功。
2. 后续运行日志显示 Rust toolchain、Cargo dependency 和 cross 至少一次命中。
3. `gh cache list` 统计缓存总量，并确认没有回到默认 10 GB 上限之上。
4. 新缓存键只包含当前锁文件哈希，不再生成旧组合键。
