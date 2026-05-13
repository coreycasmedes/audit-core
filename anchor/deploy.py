import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv, set_key
from solcx import compile_files, get_installed_solc_versions, install_solc
from web3 import Web3

SOLC_VERSION = "0.8.19"
CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
CONFIG_ENV = Path(__file__).parent.parent / "config.env"
EXPLORER = "https://explorer.hyperliquid-testnet.xyz"


def _ensure_solc() -> None:
    if SOLC_VERSION not in [str(v) for v in get_installed_solc_versions()]:
        print(f"Installing solc {SOLC_VERSION}...")
        install_solc(SOLC_VERSION)


def _compile() -> dict:
    _ensure_solc()
    return compile_files(
        [CONTRACTS_DIR / "Verifier.sol", CONTRACTS_DIR / "AuditAnchor.sol"],
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        allow_paths=[str(CONTRACTS_DIR)],
    )


def _deploy(w3: Web3, account, abi: list, bytecode: str, *args):
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(*args).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 2_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    return receipt.contractAddress, tx_hash.hex()


def main() -> None:
    load_dotenv(CONFIG_ENV)

    existing = os.getenv("AUDIT_ANCHOR_ADDRESS")
    if existing:
        print("Contracts already deployed.")
        print(f"  AuditAnchor : {existing}")
        print(f"  Explorer    : {EXPLORER}/address/{existing}")
        return

    rpc = os.getenv("HL_TESTNET_RPC", "https://rpc.hyperliquid-testnet.xyz/evm")
    key = os.getenv("HL_PRIVATE_KEY")
    if not key:
        sys.exit("HL_PRIVATE_KEY not set in config.env")

    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        sys.exit(f"Cannot connect to {rpc}")

    account = w3.eth.account.from_key(key)
    balance = w3.from_wei(w3.eth.get_balance(account.address), "ether")
    print(f"Deployer : {account.address}")
    print(f"Balance  : {balance} HYPE")
    print()

    print("Compiling contracts...")

    compiled = _compile()

    verifier_key = next(
        k for k in compiled if "Verifier" in k and "AuditAnchor" not in k
    )
    anchor_key = next(k for k in compiled if "AuditAnchor" in k)
    v_abi, v_bin = compiled[verifier_key]["abi"], compiled[verifier_key]["bin"]
    a_abi, a_bin = compiled[anchor_key]["abi"], compiled[anchor_key]["bin"]

    # Save ABIs for use by submit/receipt
    (CONTRACTS_DIR / "Verifier.abi.json").write_text(json.dumps(v_abi))
    (CONTRACTS_DIR / "AuditAnchor.abi.json").write_text(json.dumps(a_abi))

    print("Deploying Verifier...")
    v_addr, v_tx = _deploy(w3, account, v_abi, v_bin)
    print(f"  Address : {v_addr}")
    print(f"  TX      : {EXPLORER}/tx/{v_tx}")

    print("Deploying AuditAnchor...")
    a_addr, a_tx = _deploy(w3, account, a_abi, a_bin, v_addr)
    print(f"  Address : {a_addr}")
    print(f"  TX      : {EXPLORER}/tx/{a_tx}")

    set_key(str(CONFIG_ENV), "AUDIT_ANCHOR_ADDRESS", a_addr)
    set_key(str(CONFIG_ENV), "VERIFIER_ADDRESS", v_addr)

    print()
    print("Done. Contracts live.")
    print(f"  AuditAnchor : {EXPLORER}/address/{a_addr}")


if __name__ == "__main__":
    main()
