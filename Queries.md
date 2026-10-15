 # Queries

The following queries are specific to Cortex XDR/XSIAM, but should be able to be converted to the SIEM of your choosing. If not, you should be able to at least use the theory within them for own detections.

## Two Mice, One Keyboard

As discussed in the readme, it's possible to detect a KVM-over-IP device based on the presence of two mice and a keyboard associated with a single USB composite device since some devices register two mice to allow seamless transition between the absolute and relative mouse mode.  

This is either confirmed or inferred to work against the following popular devices:
* PiKVM (confirmed via testing)
* GL.iNet (confirmed via testing)
* NanoKVM Cube/Lite/Full (confirmed via testing)
* JetKVM (inferred via documentation)
* BliKVM (inferred via documentation)

The limitation with the following query is that it can only detect on **setup** (ie. first plugin). Due to the limitation of Cortex XDR's USB telemetry, you cannot easily associate two mice and a keyboard to the same composite device via XQL. You could technically make the assumption that multiple classGUIDs with the same VID/PID and serial number are part of a composite device and do a timing based solution where you detect the plugin of said devices within the same second since a composite device registers all of its devices at the same time, which would potentially catch on re-plugins and possibly reboots. This actually worked, but I experienced too many false positives with normal devices having multiple entries within the same second in the telemetry creating fake second mice to consider it a viable solution.  

Instead, I found it was more reliable to use registry data and track the initial setup, allowing me to parse out a composite device and its nodes by looking for matching VID/PID MI_nn entries, like this:
```
\VID_1D6B&PID_0104
\VID_1D6B&PID_0104\MI_00
\VID_1D6B&PID_0104\MI_01
\VID_1D6B&PID_0104\MI_02

```
But again, the caveat is this only works on first plugin. If you have 90 days worth of data and the operator plugged their device in 91 days before you run this, you will not find it. Because of that, I highly recommend setting this as a correlation rule.

I have not gotten the chance to experiment with different USB logic within different SIEMs, so there may be a better way of working this in something like Crowdstrike that has far more visibility into USB devices.

```
dataset = xdr_data
| filter event_type = ENUM.REGISTRY
    and action_registry_key_name ~= "(?i)ControlSet[0-9]+.Enum.HID.VID_"
    and action_registry_value_name = "ClassGUID"
| alter Registry_Key = arrayindex(regextract(action_registry_key_name,
            "(?i)(VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4})"), 0),
        Node     = arrayindex(regextract(action_registry_key_name,
            "(?i)Enum.HID.([A-Za-z0-9_&.{}#+-]+.[A-Za-z0-9_&.{}#+-]+)"), 0),
        Class    = if(action_registry_data ~= "(?i)4d36e96f", "mouse",
                      action_registry_data ~= "(?i)4d36e96b", "keyboard", "other"),
        _time   = format_timestamp("%Y-%m-%d %H:%M:%S", _time)
| filter Registry_Key != null and Node != null and Class != "other"
// Distinct interface nodes per class, per identity, per enumeration.
| comp count_distinct(Node) as Nodes,
       values(Node)         as Node_List
  by agent_hostname, agent_id, Registry_Key, _time, Class
// Flatten to a string before the second rollup - values() cannot aggregate an array.
| alter Node_Text = arraystring(Node_List, " ")
| comp sum(if(Class = "mouse",    Nodes, 0)) as Pointers,
       sum(if(Class = "keyboard", Nodes, 0)) as Keyboards,
       values(Node_Text)                     as Interfaces
  by agent_hostname, agent_id, Registry_Key, _time
| filter Pointers >= 2 and Keyboards >= 1
| alter Interface_Count = add(Pointers, Keyboards)
| fields agent_hostname, Registry_Key, Keyboards, Pointers, Interface_Count, Interfaces
```
Also here is a small powershell script to run on the suspected machine that checks the same thing:

```ps1
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

## Composite device with a mouse, keyboard, and non-HID device

KVM-over-IP devices simulate multiple USB devices to allow the operator to work as if they are at the machine themselves. Additional functions observed so far:
* Webcam
* Microphone
* Optical Drive
* Mass Media Storage (USB/Disk Drive)
* RNDIS Network adapter

Unlike the two mice and a keyboard query, this one uses Cortex's native USB telemetry and is able to detect devices whenever they are plugged/unplugged from the computer after setup. It requires a minimum of one mouse, one keyboard, and one non-HID device.

```
// Name: PiKVM Detection - M/K plus Non-Input USB Detection
// Description: One USB identity (composite device) exposing keyboard AND pointer 
//              plus at least one non-input function - storage, video, audio or network.
config timeframe = 30d
| dataset = xdr_data
| filter event_type = ENUM.DEVICE
// Per-endpoint, per-identity rollup. One physical plug emits one DEVICE row per
// setup class it registers, so the class list is the device's function topology.
| comp
    count_distinct(action_device_class_guid) as Setup_Class_Count,
    values(action_device_class_guid)         as Setup_Classes,
    values(action_device_usb_serial_number)  as Device_Serial,
    count()                                  as Enumeration_Events,
    earliest(_time)                          as First_Seen,
    latest(_time)                            as Last_Seen
  by agent_hostname, agent_id,
     action_device_usb_vendor_id, action_device_usb_product_id
| alter
    Keyboard = if(array_any(Setup_Classes, "@element" = "4D36E96B-E325-11CE-BFC1-08002BE10318"), "yes", "no"),
    Mouse    = if(array_any(Setup_Classes, "@element" = "4D36E96F-E325-11CE-BFC1-08002BE10318"), "yes", "no"),
    CDROM    = if(array_any(Setup_Classes, "@element" = "4D36E965-E325-11CE-BFC1-08002BE10318"), "yes", "no"),
    Disk     = if(array_any(Setup_Classes, "@element" = "4D36E967-E325-11CE-BFC1-08002BE10318"), "yes", "no"),
    Camera   = if(array_any(Setup_Classes, "@element" = "CA3E7AB9-B4C3-4AE6-8251-579EF933890F"), "yes", "no"),
    AudioEP  = if(array_any(Setup_Classes, "@element" = "C166523C-FE0C-4A94-A586-F1A80CFBBF3E"), "yes", "no"),
    MediaAud = if(array_any(Setup_Classes, "@element" = "4D36E96C-E325-11CE-BFC1-08002BE10318"), "yes", "no"),
    Network  = if(array_any(Setup_Classes, "@element" = "4D36E972-E325-11CE-BFC1-08002BE10318"), "yes", "no")
// M/K AND at least one non-input function, one identity, one host.
| filter Keyboard = "yes"
    and Mouse = "yes"
    and (CDROM = "yes" or Disk = "yes" or Camera = "yes"
         or AudioEP = "yes" or MediaAud = "yes" or Network = "yes")
| fields agent_hostname, action_device_usb_vendor_id, action_device_usb_product_id,
         Device_Serial, Setup_Class_Count,
         Setup_Classes, Keyboard, Mouse, CDROM, Disk, Camera, 
	     AudioEP, MediaAud, Network, Enumeration_Events, First_Seen, Last_Seen
| sort desc Last_Seen
```
Here is another small powershell script that accomplishes the same thing. Run with -IncludeAbsent to pick up devices that may not be currently plugged in.

```ps1
[CmdletBinding()]
param([switch]$IncludeAbsent)

$Role = @{
    kbdhid = 'Keyboard'; mouhid = 'Mouse'
    USBSTOR = 'Storage'; uaspstor = 'Storage'
    usbvideo = 'Webcam'
    usbaudio = 'Audio'; usbaudio2 = 'Audio'
    usbrndis6 = 'Network'; usbrndis5 = 'Network'; usb8023 = 'Network'; usb8023x = 'Network'; usbncm = 'Network'
}
$Enum = 'HKLM:\SYSTEM\CurrentControlSet\Enum'

$present = @{}
Get-PnpDevice -PresentOnly | ForEach-Object { $present[$_.InstanceId] = 1 }

$nodes = foreach ($bus in 'USB', 'HID') {
    foreach ($hw in Get-ChildItem "$Enum\$bus") {
        foreach ($inst in Get-ChildItem $hw.PSPath) {
            $id = "$bus\$($hw.PSChildName)\$($inst.PSChildName)"
            if (-not ($IncludeAbsent -or $present[$id])) { continue }
            $p = Get-ItemProperty $inst.PSPath
            # Skip the all-zero and all-F containers: Windows files built-in devices under them.
            if ($p.Service -and $p.ContainerID -and $p.ContainerID -notmatch '^\{00000000-0000-0000-(0000-0{12}|ffff-f{12})\}$') {
                [pscustomobject]@{ Id = $id; Hw = $hw.PSChildName; Svc = $p.Service; Container = $p.ContainerID }
            }
        }
    }
}

$hits = $nodes | Group-Object Container | ForEach-Object {
    $parent = $_.Group | Where-Object Svc -eq 'usbccgp' | Select-Object -First 1
    if (-not $parent) { return }
    $roles = @($_.Group | ForEach-Object { $Role[$_.Svc] } | Where-Object { $_ })
    $kb    = @($roles | Where-Object { $_ -eq 'Keyboard' }).Count
    $mouse = @($roles | Where-Object { $_ -eq 'Mouse' }).Count
    $extra = @($roles | Where-Object { $_ -notin 'Keyboard', 'Mouse' } | Sort-Object -Unique)
    if ($kb -and $mouse -and $extra) {
        [pscustomobject]@{
            VID = $parent.Hw -replace '.*VID_(\w{4}).*', '$1'; PID = $parent.Hw -replace '.*PID_(\w{4}).*', '$1'
            Keyboards = $kb; Mice = $mouse; Extra = $extra -join ', '
            Attached = [bool]$present[$parent.Id]
            Container = $_.Name; Parent = $parent.Id
        }
    }
}

if ($hits) { $hits } else { Write-Host 'No composite device matched keyboard + mouse + storage/webcam/audio/network' -ForegroundColor Yellow }
```
