# 更新日志

## 2025-05-02

- 现在如果存在相同名称的代理，会自动进行重命名([#175](https://github.com/7Sageer/sublink-worker/pull/175))
- 修复Singbox的DNS配置([#174](https://github.com/7Sageer/sublink-worker/pull/174))
- 更新 `sing-box` 配置生成以符合 `sing-box v1.11.0+` 规范。
  - 将已弃用的“特殊出站”（如 `type: "block"`）替换为“规则操作”（例如，广告拦截规则使用 `action: "reject"`）。
  - 此更改解决了 `sing-box` 可能出现的弃用警告，并确保了未来的兼容性。
- 增强 Sing-box 配置对 `clash_mode` 的支持。
  - DNS 解析现在能感知模式：
    - 在“direct”模式 (`clash_mode: "direct"`)下，DNS 查询主要使用直连 DNS 服务器 (例如 AliDNS DoH)。
    - 在“global”模式 (`clash_mode: "global"`)下，DNS 查询主要使用适合代理的 DNS 服务器 (例如 Cloudflare DoH，DNS 查询本身通过选定的代理路由)。
  - 此更改使常规流量路由和 DNS 行为与所选 `clash_mode` 更紧密地保持一致。
- 增强 Sing-box 特定服务组的配置。
  - 'Location:CN' (国内服务), 'Private' (私有网络), 和 'Bilibili' (哔哩哔哩) 的选择器组现在默认使用 'DIRECT' (直连) 出站。
  - 用户仍可根据需要为这些组手动选择其他选项，如 'Node Select' (节点选择) 或 'Auto Select' (自动选择)。
- 进一步优化了 Sing-box 特定服务组的默认路由和选项。
  - 'Microsoft' (微软) 和 'Apple' (苹果) 服务组现在也默认使用 'DIRECT' (直连) 出站。
  - 'DIRECT' (直连) 已作为可选路由添加至 'Social Media' (社交媒体), 'Gaming' (游戏), 'Education' (教育), 'Financial' (金融), 'Cloud Services' (云服务), 以及 'Fall Back' (回退) 选择器组中。
  - 这些更改为 Sing-box 配置中常用服务提供了更精细的控制和更合理的默认设置。

## 2025-04-30

- 完全适配Sing-Box 1.11
- 出于Github最近的限制，Balance规则集添加了`Github`

## 2025-04-27

- 提升Hysteria2协议兼容性

## 2025-04-23

- 添加俄语支持[#162](https://github.com/7Sageer/sublink-worker/issues/162)

## 2025-04-04

- Surge 改为远程规则集 (#149 by [@NSZA156](https://github.com/NSZA156))

## 2025-03-31

- 因为Deploy to Workers 的重定向问题，更新了部署方式
- 修改了部分过时的配置

## 2025-03-08

- 支持自定义UA
- 全面使用Clash Meta的Rule Provider

## 2025-02-22

- 全面支持i18n

## 2025-02-19

- 更新了 `💬 AI服务` 的路由规则

## 2025-02-18

- 添加前端i18n支持，后续会完善订阅逻辑

## 2025-01-11

- 使用代理获取规则集

## 2024-12-27

- 更新了 sing-box tun中废弃的 inet4_address 为 address

## 2024-12-07

- 确保在手动选择规则时，预定义规则集的选择框也会自动更新为 "custom"

## 2024-11-30

- 添加对 Shadowsocks 旧式 URL 的支持

## 2024-11-23

- Bug修复：
  - 重复点击生成按钮时，可能导致无法访问短链

## 2024-11-20

- 修复sing-box配置初次下载过慢的问题

## 2024-11-19

- 改进了整体UI交互体验，提升了操作流畅度

## 2024-11-05

- [新功能] 现在可以保存自定义基础配置
- 优化了UI

## 2024-10-15

- 添加了[FAQ文档](/doc/FAQ.md)

## 2024-10-03

- 现在可以保存并管理自定义短链接

## 2024-09-28

- ([#41](https://github.com/7Sageer/sublink-worker/pull/41)) (by [@Wikeolf](https://github.com/Wikeolf))
  - 添加自定义域名关键词支持
  - 现在可以决定自定义规则的顺序

## 2024-09-23

- ([#37](https://github.com/7Sageer/sublink-worker/issues/37)) 修复了VMess和Shadowsocks url中文可能出现乱码的问题

## 2024-09-20

- 在公共站点启用新域名(https://sublink-worker.sageer.me)

## 2024-09-18

- ([#35](https://github.com/7Sageer/sublink-worker/issues/35)) 确保Vmess转换时security选项存在
- 修复了默认配置缺乏出站的问题

## 2024-09-15

- ([#31](https://github.com/7Sageer/sublink-worker/issues/31),[#25](https://github.com/7Sageer/sublink-worker/issues/25)) 现在可以自定义短链接路径
- 优化了前端显示，简化操作流程

## 2024-09-13

- ([#27](https://github.com/7Sageer/sublink-worker/issues/27)) 优化了出站选择排布

## 2024-09-10

- ([#25](https://github.com/7Sageer/sublink-worker/issues/25)) 修复了Base64无法转换多个HTTP的问题
- 现在为生成的链接提供二维码

## 2024-09-09

- ([#23](https://github.com/7Sageer/sublink-worker/issues/23)) 修复了Github规则无效的问题

## 2024-09-07

- ([#16](https://github.com/7Sageer/sublink-worker/issues/16)) 修复了导入base64订阅时出现乱码的问题

## 2024-09-03

- `📚 教育资源` 现在添加了 `geosite-category-scholar-!cn` 规则

## 2024-09-02

- 现在使用 KV 存储短链接，不再依赖 R2

## 2024-09-01

- 自定义规则现在支持以下规则：
  - domain_suffix
  - ip_cidr
  - geoip
  - geosite

## 2024-08-25

- 修复 ClashMeta For Android 高于[v2.10.1]版本不显示规则集的问题

## 2024-08-20

- 新增：
  - 自定义规则
  - 自定义规则的 API 支持，详见 [API-doc.md](/doc/API-doc.md)