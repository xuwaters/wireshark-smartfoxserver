
# SFS Wireshark plugin

This wireshark plugin is used for dissecting [SmartFoxServer](http://www.smartfoxserver.com/) protocol.

## Usage

* change `sfs_ports` in `sfs.lua` to desired ports
* run from command line
`
${PATH_TO_WIRESHARK} -X lua_script:sfs.lua
`

## Known Bugs

- Reassembling SFS packet spanning multiple tcp packets may fail if missing some intermediate packets
