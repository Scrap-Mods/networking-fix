<p align="center">
  <img src="https://github.com/user-attachments/assets/37a85752-308a-402f-a818-ea5de49f0360"/>
</p>

# Networking Fix for Scrap Mechanic 🚀💣
Stops Scrap Mechanic client from stalling packets. Fixes pretty much all the networking issues.

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/scrap-mods/networking-fix/total)
![GitHub tag check runs](https://img.shields.io/github/check-runs/scrap-mods/networking-fix/v1.0.0)
[![Discord](https://img.shields.io/discord/944260227195351040?link=https%3A%2F%2Fdiscord.gg%2FahzyHPn3y2)](https://discord.gg/ahzyHPn3y2)

<p align="center">
  <video src="https://github.com/user-attachments/assets/5bc6e72e-b829-4ad9-ae29-0fd8d7e7e41d"/>
</p>
    
## How to Download and Enable 📥

There are 2 ways to enable the NetworkingFix module:

<details>
<summary><small>SM-DLL-Injector</small></summary>

1. Download the latest release of [SM-DLL-Injector](https://github.com/QuestionableM/SM-DLL-Injector/releases/latest) and follow the instructions in the [README](https://github.com/QuestionableM/SM-DLL-Injector#readme).
2. Download the latest release of `NetworkingFix.dll` [here](https://github.com/Scrap-Mods/networking-fix/releases/latest).
3. Move `NetworkingFix.dll` to `Steam/steamapps/common/Scrap Mechanic/Release/DLLModules` directory created by the SM-DLL-Injector installer.
4. Launch the game.

</details>

<details>
<summary><small>Manual Injection</small></summary>

1. Download the latest release of `NetworkingFix.dll` [here](https://github.com/Scrap-Mods/networking-fix/releases/latest).
2. Launch the game.
3. Inject `NetworkingFix.dll` using a DLL Injector of your choice.

</details>

## FAQ ❓

### How does it affect other users if you're the host? And if you're the client?
- **As the Host:** Does nothing as the host.
- **As a Client:** Improves your connection stability to the host, minimizing lag and desynchronization issues.

### Is it a trojan/virus? 🛡️
No evidence suggests this mod is a trojan or virus. However, always scan downloaded files with antivirus software to ensure safety ([VirusTotal](https://www.virustotal.com/gui/url/a9bd90fcfaadada8a2eaf43d64dcb9d72f3cb6f2d3c4b9c468f0bf03bd2993ca/details)). 

### Does it affect critical stuff like logic, physics, or other game mechanics? ⚙️
No, this mod primarily focuses on resolving network packet stalling issues and does not impact game logic, physics, or other core mechanics.

### Do I have to inject every time I want to load up the game? 💻
- **Manual Injection:** Yes, you need to inject the DLL each time you start the game.
- **Automatic Injection:** Use the [SM-DLL-Injector](#how-to-download-and-enable-) method to place the DLL in a directory where it will be loaded automatically.
