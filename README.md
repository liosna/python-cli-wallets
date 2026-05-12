# Secure Python CLI Wallets

Companion code for the MSc thesis *Design and Validation of a Security Evaluation Framework for Python CLI Wallets* (Bahçeşehir University, 2026).

This repository contains eight Bitcoin wallet prototypes that demonstrate the progressive hardening process developed and validated in the thesis.
## Prototypes

| Folder | Library    | Architecture | Role                                 |
|--------|------------|--------------|--------------------------------------|
| V0     | bit        | Non-HD       | Baseline non-HD wallet               |
| V0     | bitcoinlib | HD           | Baseline HD wallet                   |
| V1     | bit        | Non-HD       | First hardening stage                |
| V1     | bitcoinlib | HD           | First hardening stage                |
| V2     | bit        | Non-HD       | Second hardening stage               |
| V2     | bitcoinlib | HD           | Second hardening stage               |
| V3     | bit        | Non-HD       | Final hardened non-HD                |
| V3     | bitcoinlib | HD           | Final hardened HD                    |



## Requirements

- Python 3.10+
- The libraries listed in each prototype's `requirements.txt`

## Running a prototype

Each prototype is self-contained. To run one:

```bash
cd V3/bitcoinlib
pip install -r requirements.txt
python wallet.py --help
```

Replace the path with whichever version and library you want to inspect.

## Security notice

These wallets are research prototypes. They are intended to demonstrate the security patterns described in the thesis and should not be used to manage real funds on mainnet.

## Citation

If you use or reference this code, please cite:

> Ben Khadija, S. (2026). *Design and Validation of a Security Evaluation Framework for Python CLI Wallets* (Master's thesis). Bahçeşehir University.

## License

MIT (see LICENSE).
