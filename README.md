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

A **O**pen **H**armonyOS app/hap package analyze and **RE**verse tool. Maybe pronounced like "ōli".

tag: HarmonyOS, Open HarmonyOS, HarmonyOS NEXT, 鸿蒙OS, hap, app

## Features

OHRE is a full python3 tool to play with HarmonyOS .app and .hap files.

- .app and .hap
- pack.json
- module.json
- white/black list of file names in specific path
- resources.index
- .so (in progress)
- .abc (in progress)

## Installation

- Dependency: yara-python

```bash
# install as a python package locally
pip install -e . # in same dolder as setup.py
```

## How to Use

`ohre_demo.py` is a demo that shows almost all usages. Check it and then maybe check the wiki.

```bash
python ohre_demo.py xxx.hap # run demo with HarmonyOS hap
python ohre_demo.py xxx.app # run demo with HarmonyOS app
```

## Contacts

Please new an issue participate in the discussion or make a MR.
