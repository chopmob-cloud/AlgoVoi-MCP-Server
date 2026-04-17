"""Network and asset constants for the AlgoVoi MCP server."""

NETWORKS = (
    "algorand_mainnet",
    "voi_mainnet",
    "hedera_mainnet",
    "stellar_mainnet",
    "algorand_mainnet_algo",
    "voi_mainnet_voi",
    "hedera_mainnet_hbar",
    "stellar_mainnet_xlm",
)

PROTOCOLS = ("mpp", "ap2", "x402")

NETWORK_INFO = {
    "algorand_mainnet": {
        "label": "Algorand",
        "asset": "USDC",
        "asset_id": "31566704",
        "decimals": 6,
        "caip2": "algorand:mainnet",
        "description": "Circle-issued USDC on Algorand (ASA 31566704).",
    },
    "voi_mainnet": {
        "label": "VOI",
        "asset": "aUSDC",
        "asset_id": "302190",
        "decimals": 6,
        "caip2": "voi:mainnet",
        "description": "Aramid-bridged USDC on VOI (ARC-200 302190).",
    },
    "hedera_mainnet": {
        "label": "Hedera",
        "asset": "USDC",
        "asset_id": "0.0.456858",
        "decimals": 6,
        "caip2": "hedera:mainnet",
        "description": "Circle-issued USDC on Hedera (HTS 0.0.456858).",
    },
    "stellar_mainnet": {
        "label": "Stellar",
        "asset": "USDC",
        "asset_id": "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        "decimals": 7,
        "caip2": "stellar:pubnet",
        "description": "Circle-issued USDC on Stellar (trust line required).",
    },
    "algorand_mainnet_algo": {
        "label": "Algorand",
        "asset": "ALGO",
        "asset_id": None,
        "decimals": 6,
        "caip2": "algorand:mainnet",
        "description": "Native ALGO on Algorand (6 decimals, 1 ALGO = 1_000_000 microALGO).",
    },
    "voi_mainnet_voi": {
        "label": "VOI",
        "asset": "VOI",
        "asset_id": None,
        "decimals": 6,
        "caip2": "voi:mainnet",
        "description": "Native VOI on VOI network (6 decimals, 1 VOI = 1_000_000 microVOI).",
    },
    "hedera_mainnet_hbar": {
        "label": "Hedera",
        "asset": "HBAR",
        "asset_id": None,
        "decimals": 8,
        "caip2": "hedera:mainnet",
        "description": "Native HBAR on Hedera (8 decimals, 1 HBAR = 100_000_000 tinybar).",
    },
    "stellar_mainnet_xlm": {
        "label": "Stellar",
        "asset": "XLM",
        "asset_id": None,
        "decimals": 7,
        "caip2": "stellar:pubnet",
        "description": "Native XLM on Stellar (7 decimals, 1 XLM = 10_000_000 stroops).",
    },
}

CAIP2 = {k: v["caip2"] for k, v in NETWORK_INFO.items()}
