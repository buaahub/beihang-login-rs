# BeihangLogin

上网不涉密，涉密不上网！

北航网络认证 Rust 客户端（雾）

> 本软件使用 AGPL 许可证发布。
> 
> This software is released under AGPL license.

## 用户名和密码的存放

请将 `account.json.example` 文件复制为 `account.json` 文件，并存放于你运行程序的目录内，然后在其中输入你的学号和密码。

## Usage:

### 登录：

```
beihang-login
```

### 注销：

```
beihang-login -x
```

其他用法可参考：

```
beihang-login -h
```

## Gihub Workflow

如果在 Release 页面没有找到你需要的目标平台二进制文件，请使用 Github Workflow 手动构建你需要的平台二进制代码

Rust 目前支持构建的目标平台列表参见：

https://doc.rust-lang.org/nightly/rustc/platform-support.html

## 其他版本

### Python 版

隔壁BIT用的是一个版本srun

https://github.com/RogerYong/bit_srun

### Bash 版

https://github.com/buaahub/BeihangLogin
