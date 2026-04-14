# FilzaJailedDS

Filza Jailed Darksword – supports iOS 17.0–18.0.1 (except 18.7.2–18.7.7).  
This repository open-sources the tweak injected into the Filza IPA (version 4.0.0 and earlier; 4.0.2 appears to cause crashes).

Now includes SSV-protected area write access with root privileges.

## Features
- Sandbox escape via kernel exploit
- Root helper bypass
- Zip/unzip hooks
- License/integrity bypass
- Bypass Filza padlock: lets you try to create and edit files even without permission (Broken?)
- **SSV-protected area write access**: Allows writing to system-protected areas
- **Root privileges on created files**: Automatically chown files created in protected areas to root with write permissions

## Known Issues
- Filza may take 2–3 attempts before working (you can check the logs in "/tmp" inside the Filza sandbox)

## WARNING
This is a pre-release build. Most exploits are still unstable and do not always work.  
This build is for testing purposes only. Do **not** expect it to work perfectly.

If it works for you, please contact [me](https://x.com/XEmaz_) with your logs.  
If it doesn’t work, feel free to open an issue on GitHub, but **do not** contact me directly — this is a testing build.

**Note about iPhone 17 series and iPad M5**: It will **not** work because of MTE. Starting with the iPhone 17 and M5 chips, Apple added MTE which blocks kernel read/write access.

## Credits
- [Duy Tran](https://github.com/khanhduytran0) – sandbox hook token
- [wh1te4ever](https://github.com/wh1te4ever/) – darksword-kfun with offset/XPF
- [opa334](https://github.com/opa334/) – XPF/krw
- [CrazyMind90](https://github.com/crazymind90/) – idea to get sbx token with krw only
- [Huy Nguyen](https://github.com/34306/) – original repo
- [Grok](https://grok.com) and [Claude](https://claude.ai/) – assistance with the implementation
- And [me](https://x.com/XEmaz_)
- 
