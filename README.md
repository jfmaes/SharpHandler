# SharpHandler

Inspired by this [blogpost][1] from [@skelsec](https://twitter.com/SkelSec) <br>
For an in-depth explination of what this project is, please read Skelsec's excellent post! :) 
<br>
This code has been made possible due to:
* the [sharpkatz][2] project by [@b4rtik](https://twitter.com/b4rtik)
* and the [sharpdump][3] project by [@harmjoy](https://twitter.com/harmj0y)

They are the real MVP's here :) 

This project reuses open handles to lsass to parse or minidump lsass, therefore you don't need to use your own lsass handle to interact with it. 
I'm planning on getting both the P/Invoke and the D/invoke project here. Right now I'm only showing the P/Invoked version as D/invoke is making life slightly more complex. 



## caveats
Small caveat, you have to open a handle to LSASS anyway to dupe the handle, but the access level is less than you need than to parse lsass or dump it. 

bigger caveat, only X64 is supported (for now)


```
   _____ __                     __  __                ____
  / ___// /_  ____ __________  / / / /___ _____  ____/ / /__  _____
  \__ \/ __ \/ __ `/ ___/ __ \/ /_/ / __ `/ __ \/ __  / / _ \/ ___/
 ___/ / / / / /_/ / /  / /_/ / __  / /_/ / / / / /_/ / /  __/ /
/____/_/ /_/\__,_/_/  / .___/_/ /_/\__,_/_/ /_/\__,_/_/\___/_/
                     /_/

Duplicating handles to dump LSASS since 2021, inspired by @Skelsec
developed by @Jean_Maes_1994


 Usage:
  -h, -?, --help             Show Help


  -s, --scan                 Checks if there are dupeable handles to use
  -p, --process=VALUE        the process that you want to use to interact
                               with lsass (has to have a handle to lsass)
  -w, --write                Writes a minidump to location specified with -l
                               thx to sharpdump
  -c, --compress             compressess the minidump and deletes the normal
                               dump from disk (gzip format)
  -l, --location=VALUE       the location to write the minidumpfile to
  -i, --interactive          interactive mode (this mode cannot be used with
                               execute-assembly)
  -d, --dump, --logonpasswords
                             uses sharpkatz (only supports x64 architecture)
                               functionality to live parse lsass (equivalent of
                               logonpasswords)
                               
```







[1]:https://skelsec.medium.com/duping-av-with-handles-537ef985eb03
[2]: https://github.com/b4rtik/SharpKatz
[3]: https://github.com/GhostPack/SharpDump
