
## Default USB identifiers

On Windows the USB enumeration record lives under `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_yyyy\<instance>`. The key name carries the vendor and product identifiers, and the values beneath it include `DeviceDesc`, `Mfg`, `FriendlyName`, `Service`, `ContainerID`, `HardwareID` and `CompatibleIDs`. Any EDR/SIEM product that collects USB device connection events should carry the same identifiers in the event itself as well.

| VID:PID     | VID (hex) | VID (dec) | PID (hex) | PID (dec) | Serial                                       | Associated with                                          |
| ----------- | --------- | --------- | --------- | --------- | -------------------------------------------- | -------------------------------------------------------- |
| `1D6B:0104` | 1D6B      | 7531      | 0104      | 260       | CAFEBABE                                     | PiKVM default                                            |
| `1D6B:0104` | 1D6B      | 7531      | 0104      | 260       | 6b65796d696d6570690                          | TinyPilot Voyager 2A default                             |
| `1D6B:0104` | 1D6B      | 7531      | 0104      | 260       | CAFEBABE                                     | GL.iNet Comet default (v1.3.0 / v1.5.0)                  |
| `38EB:0001` | 38EB      | 14571     | 0001      | 1         | CAFEBABE                                     | GL.iNet Comet default (v1.10.1)                          |
| `38EB:0003` | 38EB      | 14571     | 0001      | 3         | CAFEBABE                                     | GL.iNet Comet observed in incident. Version unconfirmed. |
| `1D6B:0104` | 1D6B      | 7531      | 0104      | 260       | CAFEBABE (blank in serial field)             | JetKVM default                                           |
| `1D6B:0106` | 1D6B      | 7531      | 0106      | 262       | 6b65796d696d6570690                          | BliKVM default                                           |
| `3346:1009` | 3346      | 13126     | 1009      | 4105      | 0123456789ABCDEF (or blank in HID-only mode) | NanoKVM default                                          |
| `1A86:E329` | 1A86      | 6790      | E329      | 58153     | 2019B152ED98                                 | Openterface default (WCH CH9329 bridge)                  |

### GL.iNet Comet Alternate USB Identifiers

The GL.iNet Comet device comes with multiple built-in USB profiles to make the device appear as alternate devices. Since these are built-in and able to be swapped out within minutes, it is worth documenting these as potential identifiers. 
These were pulled directly from the Comet GL-RM1 v1.10.0. I am unaware if these same profiles apply to all models of the device.

| VID:PID     | VID (hex) | VID (dec) | PID (hex) | PID (dec) | Serial   | Profile                                 |
| ----------- | --------- | --------- | --------- | --------- | -------- | --------------------------------------- |
| `38EB:0001` | 38EB      | 14571     | 0001      | 1         | CAFEBABE | GL.iNet Comet default (V1.10.1)         |
| `6940:6973` | 6940      | 26944     | 6973      | 26995     | none     | Corsair Gaming RGB                      |
| `413C:2011` | 413C      | 16700     | 2011      | 8209      | none     | Dell Multimedia Pro Keyboard            |
| `045E:005F` | 045E      | 1118      | 005F      | 95        | none     | Microsoft Pro Multimedia Keyboard       |
| `046D:C526` | 046D      | 1133      | C526      | 50470     | none     | Logitech Unifying Receiver for Keyboard |

### Default EDID (virtual display) identifiers

To capture video the device has to present display identification data, and Windows records every display it has ever seen right in here:

```
HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\<identifier>\<instance>\Device Parameters
```

The value named `EDID` under that key holds the raw binary block the display supplied. The identifier in the key name is the manufacturer prefix and product code concatenated, so the values in the display table below are visible from key names alone, and the block itself carries the monitor name and serial.

| PNP ID  | Vendor prefix      | Serial          | Associated with                     |
| ------- | ------------------ | -------------- | ----------------------------------- |
| LNX777* | LNX (Linux)        | CAFEBABE       | PiKVM                               |
| TSB9876 | TSB (Toshiba)      | 2290649088     | TinyPilot                           |
| GLIC21C | GLI (GL.iNet)      | 891247         | GL.iNet Comet                       |
| TSB8801 | TSB (Toshiba)      | 2290649088     | JetKVM                              |
| VCS1145 | VCS (ViewSonic)    | 4527409        | NanoKVM                             |
| SPD3301 | SPD (Sipeed?)      | 21             | NanoKVM                             |
| HJW0001 | HJW (unregistered) | 1              | Openterface **and** BliKVM (shared) |

The first NanoKVM entry was the default EDID listed in the [Be KVM, Do Fraud](https://blog.grumpygoose.io/be-kvm-do-fraud-8ab523d26c9d) article, which was on app version 2.2.0 and 2.2.9.  
The second entry is from my own NanoKVM Cube, which provided separate identifiers on app version 2.5.2.

### GL.iNet Comet Alternate EDID Identifiers

The GL.iNet Comet device comes with multiple built-in display profiles to make the device appear as different monitors. They vary in resolution, brand, and even refresh rate. The intention is to ensure compatibility with a range of host systems, but this will obviously be used for obfuscation more than anything. It is worth having the following identifiers.
These were pulled directly from the Comet GL-RM1 v1.10.0. I am unaware if these same profiles apply to all models of the device.


| Display Profile          | PnP ID (full) | Product ID | Monitor name | Serial           | Manufacture Date | Audio (LPCM 2ch) | EDID (base64)                                                                                                                                                                                                                                                                                                                                              |
| ------------------------ | ------------- | ---------- | ------------ | --------------- | ---------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2560x1440/GLKVM/60Hz     | `GLIC21C`     | `C21C`     | `GLKVM`      | `891247`        | wk8/2021         | 32/44.1/48 kHz   | `AP///////wAdiRzCig4AAAgfAQOAPCJ4Ki1xr09EqScNUFQhCADRwJXAlQCBgIFAgcABAQEBVl4AoKCgKVAwIDUAVVAhAAAeAAAA/wA4OTEyNDcKICAgICAgAAAA/ABHTEtWTQogICAgICAgAAAA/QAwSx5yHgAKICAgICAgAV0CAyfwSxAfBRQEEwMSAhEBIwkHB4MBAABlAwwAEABoGgAAAQEwSwACOoAYcTgtQFgsRQBVUCEAAB6MCtCKIOAtEBA+lgBVUCEAABiMCtCQIEAxIAxAVQBVUCEAABjwPADQUaA1UGCIOgBVUCEAABwAAAAAAAAAAAAAAAAAAAAArg==` |
| 3840x2160/GLKVM/30Hz     | `GLIC21C`     | `C21C`     | `GLKVM`      | none            | wk9/2021         | 44.1/48 kHz      | `AP///////wAdiRzC3JMAAAkfAQOAMh94B+6Vo1RMmSYPUFQAAAABAQEBAQEBAQEBAQEBAQEBtGYAoPBwH4AwIDUAY8gQAAAaAAAA/QAX8A//GgAKICAgICAgAAAA/ABHTEtWTQogICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAV4CAxhAIwkGB2cDDAAAABA1Z9hdxAE1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmQ==` |
| 1920x1080/AOC/120Hz      | `AOC3202`     | `3202`     | `32G2WG8`    | `PGTM8JA002970` | wk32/2021        | 32/44.1/48 kHz   | `AP///////wAF4wIymgsAACAfAQSARid4KpvlrVBGpSYQUFS/7wDRwIGAMWgxfEVoRXxhaGF8U1KAoHA4L0AwIDUAuokhAAAeAAAA/wBQR1RNOEpBMDAyOTcwAAAA/AAzMkcyV0c4CiAgICAgAAAA/QAw8B7/PAAKICAgICAgAewCAzXwTBAfBRQEEwMSAhEBPyMJBweDAQAAZQMMABAAZ9hdxAF4gABtGgAAAgEw8OYAAAAAAIZvgKBwOEBAMCA1ALqJIQAAHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVA==` |
| 1920x1080/ASUS/60Hz      | `AUS24B2`     | `24B2`     | `ROG PG248Q` | `L8LMQS075392`  | wk33/2020        | 32/44.1/48 kHz   | `AP///////wAGs7IkAQEBASEeAQOANR54Du6Ro1RMmSYPUFQhCAABAQEBAQEBAQEBAQEBAQEBAjqAGHE4LUBYLEUAEyshAAAeAAAA/wBMOExNUVMwNzUzOTIgAAAA/QAYPB5aHgEKICAgICAgAAAA/ABST0cgUEcyNDhRCiAgAZkCAxrBR5AfBBMDEgEjCQcBgwEAAGUDDAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwQ==` |
| 1920x1200/EPSON/60Hz     | `SECA70B`     | `A70B`     | `EPSON PJ`   | none            | wk8/2016         | 32/44.1/48 kHz   | `AP///////wBMowunAQEBAQgaAQOAAAB4Ct5Qo1RMmSYPUFShCACBQIHAlQCBgJBAswCpQAEBKDyAoHCwI0AwIDYAQIRjAAAaniAAkFEgHzBIgDYAQIRjAAAcAAAA/QAXVQ9cEQAKICAgICAgAAAA/ABFUFNPTiBQSgogICAgARUCAyjxUZAfICIFFAQTAwISEQcGFhUBIwkHB4MBAABmAwwAIACA4gD7AjqAGHE4LUBYLEUAQIRjAAAeAR2AGHE4LUBYLEUAQIRjAAAeZiFWqlEAHjBGjzMAQIRjAAAeMCpAyGCEZDAYUBMAQIRjAAAeAAAAAAAAAAAAAAAAAAAAgA==` |
| 1920x1280/LG/60Hz        | `LG@0000`     | `0000`     | `LGD06C2`    | none            | wk53/2026        | 44.1/48 kHz      | `AP///////wAw4AAAAAAAADUkAQOAMh94B+6Vo1RMmSYPUFQAAAABAQEBAQEBAQEBAQEBAQEBNECAoHAAJVAwIDoAY8gQAAAaAAAA/QAX8A//EAAKICAgICAgAAAA/ABMR0QwNkMyCiAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAWQCAxhAIwkGB2cDDAAAABAiZ9hdxAEigAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvw==` |
| 1600x1200/HP/60Hz        | `HP@0000`     | `0000`     | `HWP2954`    | none            | wk53/2026        | 44.1/48 kHz      | `AP///////wAiAAAAAAAAADUkAQOAMh94B+6Vo1RMmSYPUFQAAAABAQEBAQEBAQEBAQEBAQEBSD9AMGKwMkBAwBMACsgQAAAeAAAA/QAX8A//EAAKICAgICAgAAAA/ABIV1AyOTU0CiAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAQsCAxhAIwkGB2cDDAAAABAhZ9hdxAEhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwQ==` |
| 2560x1440/ViewSonic/60Hz | `VSC2F34`     | `2F34`     | `VX2478-2`   | `UYL203620714`  | wk36/2020        | 32 to 192 kHz    | `AP///////wBaYzQv6lAAACQeAQOANR54Lv/VqVNFoCUNUFS/74DRwLMAqUCpwJUAkECBgIHAVl4AoKCgKVAwIDUADyghAAAaAAAA/QAyTB5THgAKICAgICAgAAAA/ABWWDI0NzgtMgogICAgAAAA/wBVWUwyMDM2MjA3MTQKAeoCAyTxT5AFBAMCBxITFBYfICEiASMJfweDAQAAZwMMABAAIEACOoAYcTgtQFgsRQAPKCEAAB4BHYAYcRwWIFgsJQAPKCEAAJ4BHQByUdAeIG4oVQAPKCEAAB4COoDQcjgtQBAsRYAPKCEAAB4BHYDQchwWIBAsJYAPKCEAAJ4AUA==` |
| 2560x1664/AOC/50Hz       | `AOC2577`     | `2577`     | `GLKVM`      | `AHLL19A000036` | wk1/2020         | 32/44.1/48 kHz   | `AP///////wAF43clJAAAAAEeAQSlNx94OkRVqVVNnSYPUFQhCADRwLMAlQCBgIFAgcABAQEBbloAoKCAKGAwIDoAKTchAAAeAAAA/QAePB5jHgAKICAgICAgAAAA/ABHTEtWTQogICAgICAgAAAA/wBBSExMMTlBMDAwMDM2AdUCAx7xSwEDBRQEEx8SAhGQIwkHB4MBAABlAwwAEAACOoAYcTgtQFgsRQApNyEAAB4BHQByUdAeIG4oVQApNyEAAB6MCtCKIOAtEBA+lgApNyEAABiMCtCQIEAxIAxAVQApNyEAABjwPADQUaA1UGCIOgApNyEAABwAAAAAAAAA0A==` |
| 2560x1600/LTM/50Hz       | `LTM3132`     | `3132`     | `ASUS`       | none            | wk32/2020        | 48 kHz           | `AP///////wAyjTIxAIiIiCAeAQOADAd4Cg3JoFdHmCcSSEwAAAABAQEBAQEBAQEBAQEBAQEBA1cAoKBAJmAwIDYAAECmAAAeAjqAGHE4LUBYLEUAxI4hAAAeAAAA/QAYZBSWHgAKICAgICAgAAAA/ABBU1VTCiAgICAgICAgAfACAx3wSgEEEB8gISJdXl8jCQQBgwEAAGUDDAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAug==` |
| 3440x1440/AOC/50Hz       | `AOC3525`     | `3525`     | `AG352UCG`   | none            | wk0/2016         | 32/44.1/48 kHz   | `AP///////wAF4yU1AQEBAQAaAQOAUiN4Du6Ro1RMmSYPUFQhCAABAQEBAQEBAQEBAQEBAQEBnWdwoNCgIlAwIDoAM1oxAAAaAAAA/wAKICAgICAgICAgICAgAAAA/QAYPB6MHgEKICAgICAgAAAA/ABBRzM1MlVDRwogICAgAW0CAxrBR5AfBBMDEgEjCQcBgwEAAGUDDAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwQ==` |
| 2560x1080/AOC/60Hz       | `AOC2963`     | `2963`     | `2963`       | none            | wk10/2013        | 32/44.1/48 kHz   | `AP///////wAF42MpSwEAAAoXAQOAQxx4KsqVplVOoSYPUFS/7wDRwLMAlQCBgIFAgcABAQEBzUYAoKA4H0AwIDoAoRwhAAAaAjqAGHE4LUBYLEUAoRwhAAAeAAAA/QAyTB5jHgAKICAgICAgAAAA/AAyOTYzCiAgICAgICAgARYCAx/xTAUUEB8EEwMSAhEBIiMJBwGDAQAAZQMMABAAAjqAGHE4LUBYLEUAoRwhAAAeAR0AclHQHiBuKFUAoRwhAAAejArQiiDgLRAQPpYAoRwhAAAYjArQkCBAMSAMQFUAoRwhAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7w==` |
| 1024x768/AOC/60Hz        | `AOCA522`     | `A522`     | `LM522`      | `T5CS88A929779` | wk35/2008        | 32/44.1/48 kHz   | `AP///////wAF4yKl8y8OACMSAQOAHheCKo89pFhNkCQVT1G/7gABAQEBAQEBAQEBAQEBAQEBZBkAQEEAJjAYiDYAMOQQAAAYAAAA/wBUNUNTODhBOTI5Nzc5AAAA/QA3Sx4/CAAKICAgICAgAAAA/ABMTTUyMgogICAgICAgAQsCAxthIwkHB4MBAABnAwwAIACALUOQhALiAA+MCtCKIOAtEBA+lgCgWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKQ==` |
| 800x600/CHR/60Hz         | `CHR7511`     | `7511`     | `CH7511B`    | none            | wk5/2013         | none             | `AP///////wANEhF1cAMAAAUXAQSVKx144oBCrFEwtCUQUFMAAAABAQEBAQEBAQEBAQEBAQEB8Q4g4DBYGCAgUDQAB0QhAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAA/QA4TB5TEQAKICAgICAgAAAA/ABDSDc1MTFCCiAgICAgABI=`                                                                                                                                                                             |
| 1600x900/AOC/60Hz        | `AOC2001`     | `2001`     | `20E1W`      | `PYGM2HA024876` | wk5/2021         | 32/44.1/48 kHz   | `AP///////wAF4wEgLGEAAAUfAQOAKxh4KlSholZPoCcQUFS/7gCpwIHAAQEBAQEBAQEBAQEBMCpAyGCEZDAYUBMAsPAQAAAeAAAA/wBQWUdNMkhBMDI0ODc2AAAA/AAyMEUxVwogICAgICAgAAAA/QAyTB5TDgAKICAgICAgAZoCAx7xSxAfBRQEEwMSAhEBIwkHB4MBAABlAwwAEACMCtCKIOAtEBA+lgCw8BAAABgBHQByUdAeIG4oVQCw8BAAAB6MCtCKIOAtEBA+lgCw8BAAABiMCtCQIEAxIAxAVQCw8BAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbQ==` |


### GL.iNet Preset Profiles

The GL.iNet Comet devices comes with three preset EDID + USB profiles. Seeing these exact device combinations would confirm the use of a GL.iNet Comet. These were pulled directly from the Comet GL-RM1 v1.10.0. I am unaware if these same profiles apply to all models of the device.

| Profile                            | EDID                                     | USB                                |
| ---------------------------------- | ---------------------------------------- | ---------------------------------- |
| **GLKVM default** (default)        | `GLI:C21C`, `GLKVM`, `891247`            | `38EB:0001`, "Comet Microphone"    |
| 1080P ASUS + Logitech Inc Keyboard | `AUS:24B2`, `ROG PG248Q`, `L8LMQS075392` | `046D:C526`, "Logitech Microphone" |
| 2K ViewSonic + Corsair Gaming RGB  | `VSC:2F34`, `VX2478-2`, `UYL203620714`   | `6940:6973`, "Corsair Microphone"  |
| 4K GLKVM + DELL Keyboard           | `GLI:C21C`, `GLKVM`, no serial           | `413C:2011`, "Dell Microphone"     |
|                                    |                                          |                                    |
