# OHRE

<p>
<a href="https://github.com/ohreteam/ohre/star"><img alt="stars" src="https://img.shields.io/github/stars/ohreteam/ohre?style=social"></a>
<a href="https://github.com/ohreteam/ohre"><img alt="watchers" src="https://img.shields.io/github/watchers/ohreteam/ohre?style=social"></a> 
<a href="https://github.com/ohreteam/ohre"><img alt="updated time" src="https://badges.pufler.dev/updated/ohreteam/ohre"></a>
<a href="https://github.com/ohreteam/ohre"><img alt="last-commit" src="https://img.shields.io/github/last-commit/ohreteam/ohre"></a>
<a href="https://github.com/ohreteam/ohre"><img alt="created time" src="https://badges.pufler.dev/created/ohreteam/ohre"></a>
<a href="https://github.com/ohreteam/ohre"><img alt="visits" src="https://badges.pufler.dev/visits/ohreteam/ohre"></a>
<a href="https://github.com/ohreteam/ohre"><img alt="license" src="https://img.shields.io/github/license/ohreteam/ohre"></a>
<a href="https://github.com/ohreteam/ohre/graphs/commit-activity"><img alt="maintained" src="https://img.shields.io/badge/Maintained%3F-yes-green.svg"></a>
</p>

史上最好用的鸿蒙解析神器来了！

OHRE，全称**开放鸿蒙应用包逆向解析工具**，念起来就像“ōli”，让你轻松解剖HarmonyOS应用包，逆向解析，无所不能！

（详细描述内容敬请期待！）

关键词：HarmonyOS, Open HarmonyOS, HarmonyOS NEXT, 鸿蒙 OS, hap, app

## 功能特色

OHRE是一款全面的Python3工具，专为HarmonyOS的.app和.hap文件而生。拥有的功能堪称核爆！

它轻而易举就能搞定你梦寐以求的鸿蒙解析需求！.app文件、.hap包、pack.json和module.json，来一个拆一个，来俩剖俩！还支持文件路径的白名单和黑名单设置、yara规则检查、resources.index解读，更别提.so和.abc文件解析正如火如荼开发中！OHRE就是这样，什么都能盘它！

- .app文件
- .hap文件
- pack.json
- module.json
- 路径中的文件名白/黑名单
- yara规则
- resources.index资源解析
- .so文件（开发中）
- .abc文件（开发中）

> 由于OHRE仍在测试中，调试日志默认保存在当前目录下，便于新建issue时追溯问题。

## 安装指南

我们就一个目标：OHRE就是要在所有平台上跑得飞起！***Windows***、***Linux***还是***macOS***，哪怕是山顶洞人用的古董机，我们也能跑得飞起！
```bash
pip install ohre # 通过pip安装 # 适合所有用户

# 作为Python包本地安装 # 适合开发者
git clone https://github.com/ohreteam/ohre.git
cd ohre
pip install -e . # 在setup.py和.git文件所在目录中执行
```

## 如何使用

OHRE的功能从来不藏着掖着！

`ohre_demo.py`是一个演示脚本，把OHRE的肌肉秀了个遍。查看它，所有功能立马在你面前亮出来！想了解更多细节？那就再看看即将到来的Wiki吧（别催还在写呢）！。

```bash
python ohre_demo.py xxx.hap # 使用演示脚本解析HarmonyOS hap包
python ohre_demo.py xxx.app # 使用演示脚本解析HarmonyOS app包
```

## 联系我们

OHRE从不单打独斗！你的问题？你的创意？新建issue！开个讨论！直接贡献代码也行！我们对你们的期待比天还高，快来加入我们，跟OHRE一起搞事情吧！