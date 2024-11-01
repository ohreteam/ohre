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

- zh_CN [简体中文](README_ZH.md)

A **O**pen **H**armonyOS app/hap package analyze and **RE**verse tool, compatible with HarmonyOS NEXT. Maybe pronounced like "ōli".

With ohre, you can (or will can) perform the following operations on a HarmonyOS app package (.app or .hap): file operations, information analysis, resource analysis, sensitive information detection, vulnerability detection, reverse analysis, etc.

tag: HarmonyOS, Open HarmonyOS, HarmonyOS NEXT, 鸿蒙 OS, hap, app

## Features

OHRE is a full python3 tool to play with HarmonyOS .app and .hap files.

- .app
- .hap
- pack.json
- module.json
- resources analysis: resources.index, resources\base\\\*, etc
- Code file leakage detection: pattern of file names in a specific path, either in white or black
- Built-in and self-defined vulnerability and sensitive information detection rules based on yara
- xxx.abc (in progress)
- xxx.so (in progress)

> Because it is still under testing, the debug log will be placed in `pwd` by default, which is one of the requirements for creating a new issue.

## Installation

As far as we know ohre is platform-independent, which means it can be used under Windows, Linux, and macOS with any CPU architecture.

```bash
pip install yara-python
pip install ohre # install from pip release version # for all users

# install as a python package locally # for debug and developers
pip install -e . # in the same folder as setup.py and .git
```

## How to Use

`ohre_demo.py` is a demo that shows almost all usages. Check it and then maybe check the wiki(TBD).

```bash
python ohre_demo.py xxx.hap # run demo with HarmonyOS hap
python ohre_demo.py xxx.app # run demo with HarmonyOS app
python ohre_demo.py xxx.hap --resource_analysis # run demo with HarmonyOS hap and resource analysis
```

## Contacts

Please new an issue, participate in the discussion or make a PR.
