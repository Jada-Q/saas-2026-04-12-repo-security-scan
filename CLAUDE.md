# saas-2026-04-12-repo-security-scan

> 输入任意 GitHub 公开仓库 URL，工具自动执行多维度安全扫描并生成统一报告。核心功能：1) 通过 GitHub API 拉取 package.json 依赖列表，批量查询 OSV.dev 免费漏洞库，按 Critical/High/Medium/Low 分级展示；2) 检测是否发布了 .map 源码映射文件（source map 泄露检测）；3) 扫描 README 和代码文件中暴露的邮箱地址、硬编码 API Key 模式（高熵字符串检测）；4) 检测仓库 URL 和贡献者名称中的 Unicode 同形字（防钓鱼）；5) 综合以上维度输出 0-100 安全评分和修复建议清单；6) 报告可一键导出为 Markdown。纯前端调用 GitHub REST API + OSV.dev API，无需登录，无需后端。

## 技术栈
- Next.js (App Router) + TypeScript
- Tailwind CSS + shadcn/ui
- pnpm

## 代码规则
- 文件：kebab-case | 组件：PascalCase | 函数：camelCase
- named export，不用 default export
- 所有样式用 Tailwind，禁止 CSS 文件
- 禁止 any，禁止 console.log
- 空状态要有友好提示

## 模式
本项目使用 auto 无人值守模式构建。
