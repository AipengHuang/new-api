# OIDC PKCE 最小补丁

官方基础版本：`QuantumNous/new-api` 的 `v1.0.0-rc.46`，提交 `7d8b91268dab69d7150f345c448b5e250163146a`。补丁分支：`feat/platform-oidc-pkce`。

参考官方 [PR #6620](https://github.com/QuantumNous/new-api/pull/6620) 的标准流程，没有整批移入该 PR 的自定义登录字段和配置界面。

## 改动边界

只给内置 `oidc` 登录补上标准授权码与 PKCE S256：每次登录生成独立随机验证值，保存在服务端；短期 HttpOnly、Secure、SameSite=Lax Cookie 绑定发起浏览器。前端只接收服务端生成的授权地址。缺少证明、浏览器不匹配或配置发生变化，都明确拒绝，不回退到无 PKCE 登录。登录、账号绑定和敏感操作验证共用该流程。

不增加数据库字段、用户匹配规则、计费逻辑、模型路由、依赖或配置开关。其他登录提供方保持官方原有逻辑。现有账号应通过官方账号绑定流程关联可信身份方的永久用户编号，不能凭邮箱相同接管账号。

New API 和 OIDC 各地址都必须使用 HTTPS。前后端需要同版发布，旧版未带 PKCE 的在途登录会被安全拒绝，用户重新发起即可；已建立的其他登录不因此批量撤销。官方页面仍是打开 `/sign-in` 后点击 OIDC 按钮，没有新增私有自动跳转接口。

本补丁没有给官方现有 UserInfo 身份查询方式补充完整的 ID Token 签名、签发方和接收方校验，不能据此声称整套 OIDC 已全面审计。

## 跟随官方升级

保留干净的官方分支，将本补丁单独放在一个提交中。选择新的官方版本后，在独立升级分支重放这一个补丁：

```sh
git fetch upstream --tags
git switch -c upgrade/oidc-pkce-RELEASE feat/platform-oidc-pkce
git rebase --onto NEW_OFFICIAL_TAG CURRENT_UPSTREAM_BASE
```

`NEW_OFFICIAL_TAG` 换成准备采用的官方版本，`CURRENT_UPSTREAM_BASE` 换成本文件当前记录的官方基础版本。每次升级验收通过后更新本文件的基础版本和提交编号，下次使用更新后的基础版本。

如果官方已实现等效的内置 OIDC PKCE 和浏览器绑定，核对后删除对应补丁。仅自定义登录支持 PKCE，不等于内置 `oidc` 已经覆盖。

升级前运行定向登录测试、前端测试和构建，再在新的数据副本验证免密登录、原账号、密钥和余额保留。不要将未验收的新程序直接连到生产数据库。补丁小可以减少升级冲突，但不能保证以后每个版本都无需检查即可部署。
