# 🛡️ ContextShield

**Pack any codebase into a token-optimized, security-hardened LLM prompt in milliseconds.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <img src="demo.svg" alt="ContextShield Terminal Demo" width="100%">
</p>

Feeding repositories into Claude, ChatGPT, or AI coding agents has three major problems:
1. **Context Window Blowup:** Dumping raw files wastes 70%+ of your tokens on boilerplate and test implementations.
2. **Accidental Secret Leaks:** Developers routinely paste hardcoded API keys, JWTs, and `.env` fallbacks into cloud LLMs.
3. **Indirect Prompt Injections:** Untrusted repositories can hide malicious instructions or invisible Trojan Source Unicode characters in comments to hijack AI coding agents.

**ContextShield** solves all three with **zero external dependencies**.

## 🚀 Quick Start

```bash
git clone [https://github.com/codexlx/contextshield.git](https://github.com/codexlx/contextshield.git)
cd contextshield
pip install -e .
```