# FastFile UI / Editor / Media Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成管理页搜索与增强筛选、上传入口合并、单文档全屏文本编辑器、普通输入框部分渲染代理层，以及音视频按需播放优化。

**Architecture:** 继续以 `index.html` 为主战场，不强行拆文件。复用现有 `mediaViewer/mediaDialog/mediaStage` 外壳，但把“文本查看器”和“全屏输入编辑器”分成两种模式：消息查看模式保留导航，单文档编辑模式移除导航并绑定当前草稿。媒体流式优化优先修前端退化点，保持后端现有 Range 响应能力不变。

**Tech Stack:** Rust + Axum 后端、单文件 HTML/CSS/Vanilla JS 前端、SQLite。

---

### Task 1: 管理页搜索与增强筛选

**Files:**
- Modify: `index.html`

- [ ] 新增管理页搜索按钮、搜索弹窗与状态样式
- [ ] 将筛选从 `select` 扩成按钮组或等价状态表达，支持：全部 / 仅文字 / 仅文件 / 图片 / 视频 / 音频
- [ ] 让搜索条件与筛选条件组合生效，并统一走 `getVisibleMessages()`
- [ ] 更新按钮颜色逻辑：搜索激活黄、非默认筛选按类型着色、恢复默认窗口在非默认时变黄

### Task 2: 上传入口收敛

**Files:**
- Modify: `index.html`

- [ ] 删除底部独立文件上传面板 DOM
- [ ] 在加号菜单中新增“文件上传”项和对应 input
- [ ] 统一图片 / 视频 / 音频 / 文件上传都走 `enqueueFiles()`
- [ ] 保持上传任务面板、断点续传和粘贴图片上传不退化

### Task 3: 单文档全屏文本编辑器

**Files:**
- Modify: `index.html`

- [ ] 在输入区按钮行新增全屏编辑按钮
- [ ] 在 `mediaViewer` 体系内新增 `editor-mode`
- [ ] 关闭上一条 / 下一条、关闭方向键切换
- [ ] 让编辑器内容与 `textInput.value` 双向同步

### Task 4: 普通输入框部分渲染代理层

**Files:**
- Modify: `index.html`

- [ ] 保留真实 textarea 作为输入源
- [ ] 为长文本输入增加可视代理层，仅渲染视口附近文本
- [ ] 滚动、选区、输入与真实 textarea 同步
- [ ] 仅在达到阈值或进入大文本状态时启用，避免普通输入复杂化

### Task 5: 音视频按需播放优化

**Files:**
- Modify: `index.html`

- [ ] 移除音频波形整文件预取 `fetch + arrayBuffer`
- [ ] 调整视频缩略图和查看器 `preload` 策略，避免激进全量预加载
- [ ] 保持 `src = file_url` 走浏览器原生 Range 流式请求
- [ ] 保留音视频进度记忆

### Task 6: 验证与文档

**Files:**
- Modify: `README.md`（如行为变化需要说明）

- [ ] 运行前端相关静态检查替代验证（DOM / 逻辑自查）
- [ ] 运行 Rust 诊断、测试、构建
- [ ] 在浏览器中验证搜索筛选、上传入口、编辑器、音视频播放
- [ ] 如用户可见行为变化明显，更新 README
