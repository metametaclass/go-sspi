package main

const hextable = "0123456789abcdef"

// HexDump alternative hex.Dump version (hex string with space)
func HexDump(buffer []byte) string {
	dst := make([]byte, 3*len(buffer))
	for i, v := range buffer {
		dst[i*3] = hextable[v>>4]
		dst[i*3+1] = hextable[v&0x0f]
		dst[i*3+2] = ' '
	}
	return string(dst)
}
