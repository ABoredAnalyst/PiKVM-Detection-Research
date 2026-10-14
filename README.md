
# Detecting Obfuscated PiKVMs (and other KVM-over-IP devices)


## What a KVM-over-IP device is

In the simplest terms, a KVM-over-IP device is a small self-contained computer, generally no bigger than a gaming controller, that lets someone remotely access another computer over a network. KVM stands for keyboard, video and mouse, which are the three main things it carries over the connection.

Setting one up only requires a few cables. At minimum, an HDMI cable that connects the computer's video output to the device, a USB cable running from the computer to the device, and an ethernet cable connecting the KVM device to the network.  Newer models, such as the GL.iNet Comet Q, can plug straight into the USB-C port of a laptop or utilize Wi-Fi instead of a hardwired connection.

Below is an example of one of the more popular KVM-over-IP models, the PiKVM..

<img width="500" height="275" alt="image" src="https://github.com/user-attachments/assets/a7c0ca45-c1ed-485e-b3da-02e6e9b379d8" />

These devices can be accessed a couple different ways, but the easiest and most common method is via the web browser. Below is an example of how the operator would open a web browser, log into the device, and access the target computer's screen. It functions no differently than a standard Teamviewer or RDP session.

<img width="700" height="450" alt="image" src="https://github.com/user-attachments/assets/bab8e0f4-685c-4620-98f7-2e4990ddfc52" />

What is important to know about these devices is that they require zero software to be installed to use on a computer. This is due to the fact that the device imitates ordinary hardware when plugged in, meaning the computer doesn't necessarily see a "PiKVM", but a standard monitor with a mouse and keyboard. 

Beyond that basic function, models differ in what else they offer. A large majority of these devices have full audio passthrough, but newer models, like the PiKVM V4+, even have webcam and microphone capabilities. This means when remoting into a computer, an operator can utilize their own headset and webcam to attend meetings on the target computer.

The KVM-over-IP category has grown quickly since the first widely used model appeared in 2017. PiKVM is the open source project most of the others descend from, and it is still the most capable of them. It will also be the main focus of our discussion, but it's not the only device being used.

Other popular models include:
- GL.iNet (another device used in our discussion)
- JetKVM
- TinyPilot 
- NanoKVM (one of the cheapest on the market)
- BliKVM
- LuckFox
- PicoKVM
- LeafKVM
- Openterface KVM-GO
- DezKVM-GO
- ArkKV

Prices start around fifty dollars and reach a few hundred. All of them are sold openly, but a majority of these are open source and can be built as well, which works in our favor when it comes to building detection logic. Because so many are built on the same open source foundation, they behave alike and a few even ship with the same default settings, which matters a great deal to anything built to detect them.

## How to detect one

There's a couple different issues that make detecting KVM-over-IP usage difficult. Like I mentioned before, the device requires no kind of driver or software install on the computer it is sharing a remote connection to. This is due to the fact that plugging a PiKVM in is no different than plugging in a mouse and keyboard, and how many security solutions can honestly say they are natively monitoring *keyboards* being plugged in, or whitelisting the exact mouse brands employees are authorized to use? 

The easiest first thing to do is begin looking for default identifiers. Like all USB devices, KVM-over-IP devices have plenty of identifiers announcing itself on several separate layers of the machine.  For example, the PiKVM and GL.iNet devices list the serial number `CAFEBABE` for all of it's emulated USB devices. They also have default naming for the monitors as well, like PiKVM showing `LNX7773` and GL.iNet showing `GLIC21C`. 

While you may not actively be monitoring for suspicious mouse and keyboards, any good EDR/SIEM system should at least have some available USB telemetry to start querying against. To help you get started, in this repo there is an Identifiers sheet with all of the observed default USB and EDID identifiers for various KVM-over-IP devices. I also listed alternate obfuscation profiles that come built into the GL.iNet Comet device that should be looked out for. While I observed the PiKVM and GL.iNet devices personally, I would like to credit GrumpyGooseLabs for their amazing article "[Be KVM Do Fraud](https://blog.grumpygoose.io/be-kvm-do-fraud-8ab523d26c9d)" that detailed everything they observed from a range of other models during their own investigations, which I have included in the list.

I have also included some queries which are specific to Cortex XDR, but you (or your preferred AI) should be able to translate them to your desired SIEM language.

This is not the end of our detection logic though. These identifiers are only the **default** ones, which means they can easily be changed and obfuscated. The GL.iNet Comet has fifteen different monitor EDIDs and five separate USB profiles built into it that span across several different brands (ASUS, Logitech, Dell, etc.), as well as allowing you to custom set your own. The PiKVM can do the same as well as directly copy the identifiers of any device plugged into it. 

Because of this, we can no longer rely on serial numbers and Vendor/Product IDs as truth and our investigation can easily take a more forensic-y turn.  We can start looking into of a potentially cloned device via the device history, or maybe possible discrepancies in naming conventions, or monitor resolutions that don't match their model, or anomalous audio endpoints (all methods covered in various other articles). 

I'm not covering all of that here though. Instead, I wanted to discuss detecting these devices via something they cannot hide or change so easily. 

And it starts with something every single KVM-over-IP device has. A USB composite device.

### USB Composite Device

In case you are unaware with the terminology, a **USB composite device** is a single piece of hardware that plugs into a computer and performs more than one function. A real world example of this that you're likely familiar with is a mouse and keyboard combo that uses a single USB unifying receiver. In the case of the PiKVM, this is how it can emulate a mouse, a keyboard, a webcam, a microphone, and other peripheral devices through a single USB connection.

This isn't to be confused with a **USB hub**, which is a device that allows you to plug multiple USB devices into a single port. Although a computer registers that a hub device is plugged in and that their are devices connected to it, each individual USB device will still receive its own separate entry in the registry with its own identifiers.

On the other hand, a composite device create a parent entry for the device as a whole, then a matching node for every interface the device declares, meaning they all share the same vendor ID and product ID in the registry.

For example, below are the registry entries for a PiKVM that has two mice, a keyboard, a webcam, an audio endpoint, and a USB storage device enabled.

```
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104\CAFEBABE
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_00\6&9f4824e&0&0000
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_01\6&9f4824e&0&0001
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_02\6&9f4824e&0&0002
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_03\6&9f4824e&0&0003
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_04\6&9f4824e&0&0004
HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_1D6B&PID_0104&MI_06\6&9f4824e&0&0006
```

The first line is the parent composite device itself, keyed on its serial number `CAFEBABE`. The `&MI_nn` suffix on the next six entries is the USB interface number associating the various functions with the main composite device. 

It should be mentioned that these specific registry entries list input devices like mice and keyboards as **HIDs** (Human Interface Device) and do not actually specify what kind of device they are. 

<img width="550" height="250" alt="image" src="https://github.com/user-attachments/assets/4000ad45-e8ba-4090-974e-8919141df902" />


That information lies within a separate registry entry beneath `Enum\HID\` sharing the same VID_PID identifier.
```
HKLM\SYSTEM\CurrentControlSet\Enum\HID\VID_1D6B&PID_0104&MI_00\7&28184a5f&0&0000
HKLM\SYSTEM\CurrentControlSet\Enum\HID\VID_1D6B&PID_0104&MI_01\7&28184a5f&0&0000
HKLM\SYSTEM\CurrentControlSet\Enum\HID\VID_1D6B&PID_0104&MI_02\7&28184a5f&0&0000
```

<img width="550" height="250" alt="image" src="https://github.com/user-attachments/assets/4bb0923b-e629-4c4a-bb0f-8ec290a3e205" />

Using this logic, we can effectively alert on a PiKVM based on the presence of a composite device that has at least:
- 2 HID devices (mouse/keyboard)
- 1 or more non-HID USB device

Based on the PiKVM's current abilities, we can classify likely non-HID devices as a webcam, an audio device, or a mass storage device.  Any combination of these under a single composite device should immediately be investigated, especially a mass storage device as this comes enabled by default on most PiKVMs.

Two warnings when forming your detection logic. Like I previously mentioned, when it comes to USB input devices like a mouse and keyboard, they are displayed as HID devices. But these are not the only devices under this category.  Common HID devices can include:
- **Keyboards and Keypads:** Standard keyboards, numerical pads, and specialized macro boards.
- **Pointing Devices:** Mice, trackballs, touchpads, trackpoints, and light pens.
- **Touchscreens and Digitizers:** Touch panels, graphics tablets, and active stylus pens.
- **Game Controllers:** Joysticks, gamepads, steering wheels, and flight simulation rudder pedals.
- **Audio and Media Controls:** Headsets, speakers, and specialized multimedia macro keys or volume knobs.
- **Sensors and Readers:** Fingerprint scanners, magnetic stripe readers, bar-code scanners, and basic environmental sensors

This means if using the registry as your reference, you will need to cross-reference the device with its `Enum\HID` entry to verify exactly what it is and make sure you are looking at a mouse and keyboard and not a mouse and keypad instead. The easiest way to do this if making queries against USB telemetry is to reference the ClassGUID of the device directly.

Below is a list of all the USB devices observed in the registry as a reference for potential detection logic.
| Device               | ClassGUID                                                         | RegistryLocation | Service   | DeviceDesc                    |
| -------------------- | ----------------------------------------------------------------- | ---------------- | --------- | ----------------------------- |
| Composite Device<br> | {36fc9e60-c465-11cf-8056-444553540000} ***                        | Enum\USB         | usbccgp   | USB Composite Device          |
| Mouse                | {4d36e96f-e325-11ce-bfc1-08002be10318}                            | Enum\HID         | mouhid    | HID-compliant mouse           |
| Keyboard             | {4d36e96b-e325-11ce-bfc1-08002be10318}                            | Enum\HID         | kbdhid    | HID Keyboard Device           |
| Mass Storage         | {36fc9e60-c465-11cf-8056-444553540000} (same as composite device) | Enum\USB         | USBSTOR   | USB Mass Storage Device       |
| Webcam               | {ca3e7ab9-b4c3-4ae6-8251-579ef933890f}                            | Enum\USB         | usbvideo  | UVC Camera                    |
| Audio                | {4d36e96c-e325-11ce-bfc1-08002be10318}                            | Enum\USB         | usbaudio2 | USB Audio 2.0                 |
| Network (RNDIS)      | {4d36e972-e325-11ce-bfc1-08002be10318}                            | Enum\USB         | usbrndis6 | Remote NDIS Compatible Device |

The RNDIS entry is definitely one to look out for as this was specifically seen enabled by default on the NanoKVM Cube.

My second warning is that the ClassGUID for a **composite device** technically belongs to the USB Controllers category, meaning that it can also be associated with generic USB hubs. This is easy to catch when doing manual reviews of the device via the registry since you can reference the DeviceDesc or Service, but can make using this logic via USB telemetry tricky depending on your SIEM as some may not expose that information.

As an example of how this could be achieved, I have provided my own query titled "M/K plus Non-Input USB Detection" for Cortex XDR.

Unfortunately, this detection logic isn't perfect because it relies on the fact that the operator uses at least one non-HID device. It is a likely occurrence due to the fact that devices like the PiKVM come with media storage enabled by default unless explicitly disabled, and the NanoKVM also comes with media storage and the RNDIS adapter enabled. But it is not guaranteed since the operators can just as easily disable these functions before hand.

At a minimum, it is still worth having an individual check for due to the chance of catching a default device, and also the fact that these operators tend to be using these devices for remote work schemes. Remote work typically means attending virtual meetings. If they don't plan to use a webcam or headset through the connection, they would either need to have a proxy stand in for them on the physical machine, or log into their accounts on a separate device, defeating the purpose of the PiKVM and likely triggering conditional access policies.

But let's say they do have a proxy standing in for them and there is no chance they will ever be seen using anything besides the mouse and keyboard. This logic is busted, but our next one might make up for it.

## 2 Mice, 1 Keyboard

Looking for a PiKVM based off of a composite device with just a mouse and keyboard would be like looking for a needle in a haystack since M/K combos are probably one of the most common use cases for a composite device. But what if the needle was shaped like **two** mice and a keyboard instead?

You may have noticed when we listed off the registry entries for the PiKVM device earlier that there were two mice and one keyboard listed for the device. It's not the oddest thing in the world to see multiple mice on a single computer, but when both are registered to a single composite device alongside a keyboard, that's enough to set off some alarms. 

Why does it have two mice though? For compatibility reasons, most KVM devices come with two separate mouse modes to choose from: absolute and relative.
- **Absolute** mode transmits the exact screen coordinates of the cursor to the target computer and allows them to freely move their mouse in and out of the stream window. This is the default mouse for most all KVM devices that will be used.
- **Relative** mode traps their cursor within the stream and forces them to click in and out the session. This is occassionally used because BIOS/UEFI menus sometimes don't support absolute mode.

Each mode requires its own individual mouse. The reason being is that a singular mouse cannot simply swap between the two modes since this state is set in the USB device report descriptor and registered to the computer upon plugin. 

Some KVM models only register a single mouse and require the operator to reboot the device in order to swap modes. Others solved this this problem by simultaneously simulating two separate mice on the computer to allow the operator to seamlessly swap back and forth between the two, granting us this detection logic in kind.

For reference, below is a screenshot from the PiKVM GUI showing this feature:

<img width="334" height="262" alt="image" src="https://github.com/user-attachments/assets/6712219b-c208-4159-b8ca-977eb83cafcf" />

We'll discuss the specifics of these mouse modes and how they function in the next section, but what's important to take away from this is that multiple KVM devices share this seamless mouse switching capability, potentially giving this detection method a relatively broad scope. 

Here is a list of all of the device this method is believed to work against:
- PiKVM (confirmed via testing)
- GL.iNet (confirmed via testing)
- NanoKVM Cube/Lite/Full (confirmed via testing)
- JetKVM (inferred via documentation)
- BliKVM (inferred via documentation)

Since we are going off of device presence instead of looking for identifiers, this means that it is possible to detect any of these devices even after obfuscation with zero additional peripherals (webcam, mass storage, audio) by simply looking for a composite device that has two mice and a keyboard associated with it. 

I'll admit that the logic for this can again be tricky depending on the USB telemetry your EDR provides. I have a query specific to Cortex XDR titled "Keyboard plus two pointers" that you may be able to translate to your desired platform's language. To quickly prove this logic though, I've also included a simple powershell script below as a reference for how something like this could be detected when observing a machine directly. 

```
Get-PnpDevice -PresentOnly -Class Mouse,Keyboard |
  ForEach-Object {
    [pscustomobject]@{
      Class     = $_.Class
      Friendly  = $_.FriendlyName
      InstanceId= $_.InstanceId
      Container = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_ContainerId).Data
    }
  } |
  Group-Object Container |
  Where-Object {
    (($_.Group | Where-Object Class -eq 'Mouse').Count -ge 2) -and
    ($_.Group.Class -contains 'Keyboard')
  } |
  ForEach-Object { $_.Group } |
  Format-Table Class, Friendly, Container, InstanceId -AutoSize
```

An example of it finding an obfuscated PiKVM:

<img width="911" height="121" alt="image" src="https://github.com/user-attachments/assets/1e831774-7bc0-403e-80ea-f6344c76b8af" />

And my default GL.iNet Comet:

<img width="911" height="121" alt="image" src="https://github.com/user-attachments/assets/6e300faf-7798-440c-90dd-0a929cdd1483" />

While this method theoretically should work for a majority of the aforementioned KVM-over-IP devices, it has only been tested against a PiKVM V4+ and a GL.iNet Comet on firmware v1.10.1. It was noted during testing that the original firmware version the Comet came with (v1.1.3) did not have the seamless mouse switching capability, so it only registered a single mouse. The capability was not introduced to the Comet until v1.4.0 (July 2025), meaning older models will go undetected.

All PiKVM models and firmware versions since 2020 have this capability, but the seamless mode only comes enabled by default on the V4 series. All prior models require the user to manually enable it.

The two mice, one keyboard method covers a lot of ground, but there is still a large chunk of devices this won't apply to. With only one mouse present, there is still one trick to investigating it, and it lies behind the mouse mode itself.

## Absolute Mouse

First, let's discuss the two mouse modes previously mentioned a bit more in depth.

#### Relative
A relative mouse reports **movement deltas**: when you move your physical mouse to the right and down, it tells the computer "the pointer moved +4 units in X and −2 in Y." Your physical mouse has no notion of where the cursor is on the screen. The operating system takes the delta, applies its own pointer-acceleration curve and sensitivity settings, and moves the cursor from wherever it currently sits based on how far you moved your mouse.  What's important to take away from this is that **this is the mode that all standard physical mice use on a desktop.**
#### Absolute
Instead of reporting movements, an absolute mouse constantly reports a **fixed coordinate**: "the pointer is at position X=8000, Y=3200". That coordinate maps directly onto the screen, so the cursor jumps to the corresponding point regardless of where it was. This is how graphics tablets, touchscreens, and touch digitizers work, and it's why a stylus tap lands exactly where you touched rather than nudging the cursor from its last spot. This is also how most remote software solutions, like VMware Horizon or RDP, register the mouse inside their sessions so that you can easily move your mouse in and out of the window without having to lock your mouse to it. 

Almost all KVM-over-IP devices use **Absolute mode** by default since it is the most compatible with browser sessions. Relative mode **can** technically be used, but it usually isn't advised because constant usage can lead to cursor de-synchronization between the local and remote mouse. It is generally reserved for older legacy systems, the BIOS/UEFI screens, or troubleshooting.

To simplify the point I'm trying to make: because almost all physical mice register as a relative mouse, that fact alone could consider an absolute mouse an **anomaly**. If you were to see this on a computer and were able to verify that the computer isn't hosting a remote session (RDP, VMWare Horizon, Citrix), then you very well could be looking at a potential PiKVM device.

So how do we figure out if a mouse is in absolute mode or relative?

When plugged in, a mouse (or any USB HID device) describes itself through a **report descriptor** which is a compact binary blob that it hands the host at enumeration that declares every field it will send: what each byte means, its usage (X axis, Y axis, button, wheel), its logical range, and a set of flags per field. One of those flags, bit 2 of the Input item, is the **Absolute/Relative** bit. 

Below is a screenshot of those bit fields for a PiKVM mouse using [USBTreeViewer](https://www.uwe-sieber.de/usbtreeview_e.html#download), a free program that helps us decode USB device descriptors.:

<img width="445" height="276" alt="image" src="https://github.com/user-attachments/assets/aef7dab8-30b2-44e6-bd57-ebbf212cde24" />

As you can see in Bit 2, it is registered as Absolute with a value of 0. Down towards the bottom, it is also shown via an additional flag, IsAbsolute. For comparison, here is a standard mouse, which has a value of 1, declaring it Relative.

<img width="445" height="276" alt="image" src="https://github.com/user-attachments/assets/dc59eab1-9dc2-43bb-b5e2-bbf55501322f" />

What makes detecting this so tricky is the fact that the axis mode never gets promoted to a setup class property, a WMI field, or anything that something like Get-PnpDevice or Device Manager could see. It gets cached and only passes along what is necessary, such as the vendor ID, product name, device class, and the like.  That means the only way to recover that information is to go back through the cached descriptor itself and read the flag directly. 

To do that, you would have to either use a program like USBTreeViewer or script a way to interact with the HID parsing APIs directly. With a large chunk of help from my good friend Claude, I was able to put together a powershell script with a bit of embedded C# that does exactly that, called [hid_axis_mode](https://github.com/ABoredAnalyst/PiKVM-Detection-Research/blob/69f12529021f0d9fd0488e082f96198a87c886ab/Scripts/Mouse%20Detection/hid_axis_mode.ps1). To put it simple, the script goes through each mouse connected to the machine, checks its axis mode, and let's you know if it's relative or absolute. Below is an example of it picking up on an obfuscated PiKVM mouse.

<img width="637" height="233" alt="image" src="https://github.com/user-attachments/assets/fbec5de7-f11d-4036-bc4d-ae5087abced7" />

Here is another example from a default GL.iNet Comet:

<img width="637" height="233" alt="image" src="https://github.com/user-attachments/assets/9c84d1ec-673f-474a-bf51-8ecd2a8e25b2" />

You can also note that in each screenshot that there are two mice with the same VID and PID, indicating these are likely joined via a composite device (although checking for composite devices isn't part of this current scripts functionality, this is just an observation.) One mouse is relative, while the other is absolute, which would be a strong indicator that this likely belongs to a KVM-over-IP device and likely would've triggered our previous logic around two mice and a keyboard.

When running this across my environment of 1,100 machines I only had one false positive, which was a Corsair gaming keyboard that had macro keys enabled. I'll admit that the output and reporting could be cleaned up for some better automation, but it gets the job done for the time being. I'm sure this can be developed over time though and cleaner methods may come to light. 

Unfortunately, since EDR services do not reveal this level of detail when a USB device is used (likely due to the level of noise that would be included), this doesn't strike me as the kind of thing you can actively monitor for via a query or a correlation rule, but would instead need to perform an occasional audit or a monthly scan for. Complications aside, I still believe this method could hold a lot of weight and be incredibly useful, such as when you have suspicions of a specific machine and need that last nail to drive into the coffin.


*** Work in progress. Further detection discussions may be added later on. ***
