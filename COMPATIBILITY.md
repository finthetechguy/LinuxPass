# Compatibility

## Wireless Chipsets/Adapters

_If your adapter is not listed, it is unlikely to work, although you can test anyway._

| Status | Chipset / Adapters | Linux driver | Mode | Notes |
|---|---|---|---|---|
| ✅ Tested, works | Qualcomm Atheros AR92xx / AR93xx / AR946x / AR9485 / QCA9565 (PCIe) | `ath9k` | Active monitor | **Recommended.** Full exchanges with a 3DS family console. |
| ✅ Tested, works | Realtek RTL8192EU, e.g. TP-Link TL-WN823N v2/v3 (USB) | `rtl8xxxu` | Mixed | Slower, successfully exchanges. |
| 🟡 Expected, untested | MediaTek MT7610U / MT7612U, e.g. Alfa AWUS036ACHM, AWUS036ACM, Netgear A6210 (USB) | `mt76x0u`, `mt76x2u` | Active monitor | Others report active monitor ACKing correctly on these. |
| 🟡 Expected, untested | MediaTek MT7601U, cheap 2.4 GHz "150 Mbps" USB sticks | `mt7601u` | Active monitor | Only one interface can be up at a time. |
| 🟡 Untested | Realtek RTL8188EU/CU/FU, RTL8192CU, RTL8723BU | `rtl8xxxu` | Mixed | Same driver as the tested RTL8192EU, so mixed mode might work. |
| 🟡 Untested | Realtek RTL8812BU / RTL8822BU / RTL8821CU / RTL8822CU (USB) | `rtw88` | Mixed | The driver programs the station's MAC into hardware, so mixed mode should ACK. |
| 🟡 Untested | Ralink RT3070 / RT5370 / RT5572 (USB) | `rt2800usb` | Mixed | The hardware can ACK a set MAC; not tried through the kernel driver yet. |
| 🟡 Untested | Atheros AR9271, e.g. Alfa AWUS036NHA, TP-Link TL-WN722N v1 (USB) | `ath9k_htc` | Mixed | No active monitor (unlike PCIe `ath9k`). |
| 🟡 Untested | MediaTek MT7603, MT7615, MT7663, MT7915/MT7916, MT7996 (mostly routers and M.2 cards) | `mt76` | Active monitor | Advertises active monitor, but the firmware decides whether it really ACKs. |
| ❌ Does not work | MediaTek MT7921 / MT7922 / MT7902 / MT7925 / MT7927 (common in laptops) | `mt7921e/u/s`, `mt7925e/u` | n/a | The firmware stops receiving in active monitor and doesn't send injected frames. |
| ❌ Not expected to work | Intel Wi-Fi (AX200, AX210, BE200, …) | `iwlwifi` | n/a | No active monitor; injection support is limited. |
| ❌ Does not work | Broadcom | `brcmfmac`, `wl` | n/a | No monitor-mode injection. |
| ❌ Not expected to work | Qualcomm Wi-Fi 5/6/7 (QCA6174, QCA9377, WCN685x, …) | `ath10k`, `ath11k`, `ath12k` | n/a | No active monitor; injection not usable for this. |

<details>
<summary>Active monitor vs Mixed</summary>
<br>
<b>Active monitor:</b>
The driver can make one monitor interface both inject frames and ACK the peer.
It can also change channel (1, 6, 11) for some drivers, if not, it defaults to channel 1.

<b>Mixed:</b>
Two virtual interfaces are created on the same adapter. A monitor interface that sends and listens, and an unconnected station interface which carries Tuxchange's own MAC address to the hardware ACKs the console's frames.
It can only stay on channel 1.
</details>
