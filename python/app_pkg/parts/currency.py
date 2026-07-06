"""CENTRAL currency part — the ISO-4217 closed set of active circulating currency codes. A money domain validates a
`currency` field against THIS set, not merely "well-formed" (a charge in 'xyz' is a data-integrity hole). The check is
case-insensitive (Stripe-style lowercase 'usd' and ISO 'USD' both resolve). The X-prefixed NON-TENDER codes — precious
metals (XAU/XAG/XPT/XPD), fund/bond-market units, XDR (IMF SDR), XTS (test), XXX (no currency) — are EXCLUDED as
non-spendable; the real X currencies (XAF/XOF/XCD/XPF) are INCLUDED. One source ×3, byte-identical, proven by vectors."""
_CODES = frozenset((
    "AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BRL BSD BTN BWP BYN BZD "
    "CAD CDF CHF CLP CNY COP CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD "
    "GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT "
    "LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MYR MZN NAD NGN NIO NOK NPR "
    "NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP "
    "STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD UYU UZS VED VES VND VUV WST XAF XCD "
    "XOF XPF YER ZAR ZMW ZWG"
).split())


def is_currency(code: str) -> bool:
    """True iff `code` is an active ISO-4217 currency code (case-insensitive)."""
    return isinstance(code, str) and code.upper() in _CODES
