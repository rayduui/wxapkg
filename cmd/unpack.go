package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/wux1an/wxapkg/util"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

var programName = filepath.Base(os.Args[0])
var unpackCmd = &cobra.Command{
	Use:     "unpack",
	Short:   "Decrypt wechat mini program",
	Example: "  " + programName + "unpack -o unpack -r \"D:\\WeChat Files\\Applet\\wx12345678901234\"",
	Run: func(cmd *cobra.Command, args []string) {
		root, _ := cmd.Flags().GetString("root")
		output, _ := cmd.Flags().GetString("output")
		thread, _ := cmd.Flags().GetInt("thread")
		disableBeautify, _ := cmd.Flags().GetBool("disable-beautify")

		// Check if the path directly points to a directory containing __APP__.wxapkg
		appPath := filepath.Join(root, "__APP__.wxapkg")
		if _, err := os.Stat(appPath); err == nil {
			color.Cyan("[+] Found __APP__.wxapkg directly in specified path\n")
			
			// Extract wxid from parent directory
			parentDir := filepath.Base(filepath.Dir(root))
			wxid, err := parseWxid(parentDir)
			if err != nil {
				color.Red("[!] Failed to parse wxid: %v\n", err)
				return
			}
			
			// Unpack the single file
			var decryptedData = decryptFile(wxid, appPath)
			fileCount, err := unpack(decryptedData, output, thread, !disableBeautify)
			if err != nil {
				color.Red("[!] %v\n", err)
				return
			}
			
			color.Yellow("[+] Unpacked %d files from '%s'\n", fileCount, appPath)
			color.Cyan("[+] All %d files saved to '%s'\n", fileCount, output)
			return
		}

		wxid, err := parseWxid(root)
		if err != nil {
			color.Red("[!] Failed to parse wxid: %v\n", err)
			return
		}

		dirs, err := os.ReadDir(root)
		if err != nil {
			color.Red("[!] Failed to read directory: %v\n", err)
			return
		}

		color.Cyan("[+] unpack root '%s' with %d threads\n", root, thread)

		var allFileCount = 0
		for _, subDir := range dirs {
			// Skip .DS_Store files on macOS
			if subDir.Name() == ".DS_Store" {
				continue
			}
			
			subOutput := filepath.Join(output, subDir.Name())

			// Try to find wxapkg files - first direct, then scan all subdirectories
			var files []string
			
			// 1. Try direct path
			subDirPath := filepath.Join(root, subDir.Name())
			directAppPath := filepath.Join(subDirPath, "__APP__.wxapkg")
			if _, err := os.Stat(directAppPath); err == nil {
				files = append(files, directAppPath)
			} else {
				// 2. Scan for .wxapkg files at this level
				wxapkgFiles, err := util.GetDirAllFilePaths(subDirPath, "", ".wxapkg")
				if err == nil && len(wxapkgFiles) > 0 {
					files = append(files, wxapkgFiles...)
				} else {
					// 3. Try to scan subdirectories (including numeric ones like "161")
					subDirs, err := os.ReadDir(subDirPath)
					if err == nil {
						for _, sDir := range subDirs {
							if !sDir.IsDir() {
								continue
							}
							
							deeperPath := filepath.Join(subDirPath, sDir.Name())
							appPath := filepath.Join(deeperPath, "__APP__.wxapkg")
							if _, err := os.Stat(appPath); err == nil {
								files = append(files, appPath)
							}
						}
					}
				}
			}
			
			if len(files) == 0 {
				continue
			}

			for _, file := range files {
				var decryptedData = decryptFile(wxid, file)
				fileCount, err := unpack(decryptedData, subOutput, thread, !disableBeautify)
				if err != nil {
					color.Red("\r[!] %v", err)
					continue
				}
				allFileCount += fileCount

				rel, _ := filepath.Rel(filepath.Dir(root), file)
				color.Yellow("\r[+] unpacked %5d files from '%s'", fileCount, rel)
			}
		}

		color.Cyan("[+] all %d files saved to '%s'\n", allFileCount, output)
		if len(args) == 2 && "detailFilePath" == args[0] {
			color.Cyan("[+] mini program detail info saved to '%s'\n", args[1])
		}

		color.Cyan("[+] extension statistics:\n")

		var keys [][]interface{}
		for k, v := range exts {
			keys = append(keys, []interface{}{k, v})
		}

		sort.Slice(keys, func(i, j int) bool {
			return keys[i][1].(int) > keys[j][1].(int)
		})

		for _, kk := range keys {
			color.Cyan("  - %-5s %5d\n", kk[0], kk[1])
		}
	},
}

type wxapkgFile struct {
	nameLen uint32
	name    []byte
	offset  uint32
	size    uint32
}

func unpack(decryptedData []byte, unpackRoot string, thread int, beautify bool) (int, error) {
	if decryptedData == nil || len(decryptedData) < 10 {
		return 0, errors.New("invalid decrypted data (nil or too small)")
	}

	// Check for potential Mac format (examine first bytes)
	var firstBytes []byte
	if len(decryptedData) >= 20 {
		firstBytes = decryptedData[:20]
		hexStr := fmt.Sprintf("% x", firstBytes)
		color.Cyan("First 20 bytes: %s", hexStr)
	}

	// Try to parse wxapkg in several formats
	
	// APPROACH 1: Standard format (Windows wxapkg format)
	color.Cyan("Trying standard wxapkg format parsing...")
	if result, err := tryStandardUnpack(decryptedData, unpackRoot, thread, beautify); err == nil {
		return result, nil
	} else {
		color.Yellow("Standard format failed: %v", err)
	}
	
	// APPROACH 2: Try different formats for macOS
	color.Cyan("Trying macOS alternative formats...")
	
	// Try to find a valid wxapkg structure by scanning for file entries
	if result, err := tryMacOSUnpack(decryptedData, unpackRoot, thread, beautify); err == nil {
		return result, nil
	} else {
		color.Yellow("macOS format failed: %v", err)
	}
	
	// APPROACH 3: Try direct file extraction (PK-like approach)
	// Skip for now, would require more analysis of file format
	
	return 0, errors.New("could not identify a valid wxapkg structure in the file")
}

// Standard unpacking method that expects BE ED markers
func tryStandardUnpack(decryptedData []byte, unpackRoot string, thread int, beautify bool) (int, error) {
	var f = bytes.NewReader(decryptedData)

	// Read header
	var (
		firstMark       uint8
		info1           uint32
		indexInfoLength uint32
		bodyInfoLength  uint32
		lastMark        uint8
	)
	
	if err := binary.Read(f, binary.BigEndian, &firstMark); err != nil {
		return 0, fmt.Errorf("failed to read first mark: %v", err)
	}
	
	if err := binary.Read(f, binary.BigEndian, &info1); err != nil {
		return 0, fmt.Errorf("failed to read info1: %v", err)
	}
	
	if err := binary.Read(f, binary.BigEndian, &indexInfoLength); err != nil {
		return 0, fmt.Errorf("failed to read indexInfoLength: %v", err)
	}
	
	if err := binary.Read(f, binary.BigEndian, &bodyInfoLength); err != nil {
		return 0, fmt.Errorf("failed to read bodyInfoLength: %v", err)
	}
	
	if err := binary.Read(f, binary.BigEndian, &lastMark); err != nil {
		return 0, fmt.Errorf("failed to read lastMark: %v", err)
	}

	color.Cyan("Header values: firstMark=0x%02x, lastMark=0x%02x, info1=%d, indexLen=%d, bodyLen=%d", 
		firstMark, lastMark, info1, indexInfoLength, bodyInfoLength)

	if firstMark != 0xBE || lastMark != 0xED {
		return 0, fmt.Errorf("invalid wxapkg markers: 0x%02x, 0x%02x (expected 0xBE, 0xED)", firstMark, lastMark)
	}

	var fileCount uint32
	if err := binary.Read(f, binary.BigEndian, &fileCount); err != nil {
		return 0, fmt.Errorf("failed to read fileCount: %v", err)
	}

	color.Cyan("File count: %d", fileCount)
	
	if fileCount > 10000 || fileCount == 0 {
		return 0, fmt.Errorf("suspicious file count: %d (too large or zero)", fileCount)
	}

	// Read index
	var fileList = make([]*wxapkgFile, fileCount)
	for i := uint32(0); i < fileCount; i++ {
		data := &wxapkgFile{}
		if err := binary.Read(f, binary.BigEndian, &data.nameLen); err != nil {
			return 0, fmt.Errorf("failed to read name length for file %d: %v", i, err)
		}

		if data.nameLen > 10<<20 || data.nameLen == 0 { // 10 MB or 0
			return 0, fmt.Errorf("invalid name length for file %d: %d (too large or zero)", i, data.nameLen)
		}

		data.name = make([]byte, data.nameLen)
		n, err := io.ReadAtLeast(f, data.name, int(data.nameLen))
		if err != nil || n != int(data.nameLen) {
			return 0, fmt.Errorf("failed to read name for file %d (read %d/%d bytes): %v", 
				i, n, data.nameLen, err)
		}
		
		if err := binary.Read(f, binary.BigEndian, &data.offset); err != nil {
			return 0, fmt.Errorf("failed to read offset for file %d: %v", i, err)
		}
		
		if err := binary.Read(f, binary.BigEndian, &data.size); err != nil {
			return 0, fmt.Errorf("failed to read size for file %d: %v", i, err)
		}

		fileList[i] = data
		
		if i < 3 { // Print details of first few files for debugging
			color.Cyan("File %d: name=%s, offset=%d, size=%d", 
				i, string(data.name), data.offset, data.size)
		}
	}

	// Create the output directory
	if err := os.MkdirAll(unpackRoot, os.ModePerm); err != nil {
		return 0, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Extract files
	return extractFiles(fileList, decryptedData, unpackRoot, thread, beautify)
}

// Try to parse macOS wxapkg format
func tryMacOSUnpack(decryptedData []byte, unpackRoot string, thread int, beautify bool) (int, error) {
	// In this method, we're going to look for specific byte patterns
	// that might indicate a different format for macOS
	
	// First check if it's just a different header format
	if len(decryptedData) < 20 {
		return 0, errors.New("file too small for alternative format")
	}
	
	// Try different potential offsets where the wxapkg data might start
	for offset := 0; offset < 20; offset++ {
		if offset+6 >= len(decryptedData) {
			break
		}
		
		// Try this offset as a potential start of the file
		testData := decryptedData[offset:]
		reader := bytes.NewReader(testData)
		
		// Check if there's a consistent file structure
		var fileCount uint32
		
		// Skip the first 6 bytes (potential header)
		reader.Seek(6, io.SeekStart)
		
		// Try to read fileCount
		if err := binary.Read(reader, binary.BigEndian, &fileCount); err != nil {
			continue
		}
		
		// Sanity check on fileCount
		if fileCount == 0 || fileCount > 10000 {
			continue
		}
		
		color.Cyan("Found potential macOS format at offset %d with %d files", offset, fileCount)
		
		// Let's try to read the file entries
		var fileList = make([]*wxapkgFile, fileCount)
		var validEntries = true
		
		for i := uint32(0); i < fileCount; i++ {
			data := &wxapkgFile{}
			if err := binary.Read(reader, binary.BigEndian, &data.nameLen); err != nil {
				validEntries = false
				break
			}
			
			// Sanity check on name length
			if data.nameLen == 0 || data.nameLen > 1000 {
				validEntries = false
				break
			}
			
			data.name = make([]byte, data.nameLen)
			n, err := io.ReadAtLeast(reader, data.name, int(data.nameLen))
			if err != nil || n != int(data.nameLen) {
				validEntries = false
				break
			}
			
			// Check if the name contains only valid characters
			if !isValidFilename(string(data.name)) {
				validEntries = false
				break
			}
			
			if err := binary.Read(reader, binary.BigEndian, &data.offset); err != nil {
				validEntries = false
				break
			}
			
			if err := binary.Read(reader, binary.BigEndian, &data.size); err != nil {
				validEntries = false
				break
			}
			
			// Sanity check on offset and size
			if data.offset >= uint32(len(testData)) || data.offset+data.size > uint32(len(testData)) {
				validEntries = false
				break
			}
			
			fileList[i] = data
			
			if i < 3 {
				color.Cyan("File %d: name=%s, offset=%d, size=%d", 
					i, string(data.name), data.offset, data.size)
			}
		}
		
		if !validEntries {
			color.Yellow("Format at offset %d has invalid entries, skipping", offset)
			continue
		}
		
		// Create the output directory
		if err := os.MkdirAll(unpackRoot, os.ModePerm); err != nil {
			return 0, fmt.Errorf("failed to create output directory: %v", err)
		}
		
		// If we got here, we have a potential valid file list
		color.Green("Found valid macOS format wxapkg at offset %d", offset)
		
		// Extract the files
		return extractFiles(fileList, testData, unpackRoot, thread, beautify)
	}
	
	return 0, errors.New("no valid macOS wxapkg format found")
}

// Helper to check if a filename looks valid
func isValidFilename(name string) bool {
	if len(name) == 0 {
		return false
	}
	
	// Check if it contains common file extensions or paths
	validExtensions := []string{".js", ".json", ".html", ".css", ".wxml", ".wxss"}
	for _, ext := range validExtensions {
		if strings.Contains(name, ext) {
			return true
		}
	}
	
	// Check for other indications of a valid path
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return true
	}
	
	return false
}

// Extract files from fileList
func extractFiles(fileList []*wxapkgFile, decryptedData []byte, unpackRoot string, thread int, beautify bool) (int, error) {
	// Save files
	var chFiles = make(chan *wxapkgFile)
	var wg = sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, d := range fileList {
			// Check if offset and size are within bounds
			if d.offset >= uint32(len(decryptedData)) || 
			   d.offset+d.size > uint32(len(decryptedData)) {
				color.Red("Warning: File %s has invalid bounds (offset=%d, size=%d, data_len=%d)", 
					string(d.name), d.offset, d.size, len(decryptedData))
				continue
			}
			chFiles <- d
		}
		close(chFiles)
	}()

	wg.Add(thread)
	var locker = sync.Mutex{}
	var count = 0
	var colorPrint = color.New()
	var errors = make([]string, 0)
	
	for i := 0; i < thread; i++ {
		go func() {
			defer wg.Done()

			for d := range chFiles {
				d.name = []byte(filepath.Join(unpackRoot, string(d.name)))
				outputFilePath := string(d.name)
				dir := filepath.Dir(outputFilePath)

				if err := os.MkdirAll(dir, os.ModePerm); err != nil {
					locker.Lock()
					errors = append(errors, fmt.Sprintf("Failed to create directory %s: %v", dir, err))
					locker.Unlock()
					continue
				}

				// Check if offset and size are valid
				if d.offset >= uint32(len(decryptedData)) || d.offset+d.size > uint32(len(decryptedData)) {
					locker.Lock()
					errors = append(errors, fmt.Sprintf("Invalid offset/size for %s: offset=%d, size=%d, data_len=%d", 
						outputFilePath, d.offset, d.size, len(decryptedData)))
					locker.Unlock()
					continue
				}

				data := decryptedData[d.offset : d.offset+d.size]

				if beautify {
					data = fileBeautify(outputFilePath, data)
				}
				
				if err := os.WriteFile(outputFilePath, data, 0600); err != nil {
					locker.Lock()
					errors = append(errors, fmt.Sprintf("Failed to write file %s: %v", outputFilePath, err))
					locker.Unlock()
					continue
				}

				locker.Lock()
				count++
				_, _ = colorPrint.Print(color.GreenString("\runpack %d/%d", count, uint32(len(fileList))))
				locker.Unlock()
			}
		}()
	}

	wg.Wait()
	
	// Report any errors
	if len(errors) > 0 {
		color.Yellow("\nEncountered %d errors during unpacking:", len(errors))
		for i, err := range errors {
			if i < 5 { // Only show first 5 errors
				color.Yellow("  - %s", err)
			} else if i == 5 {
				color.Yellow("  - ... and %d more errors", len(errors)-5)
				break
			}
		}
	}

	return count, nil
}

var exts = make(map[string]int)
var extsLocker = sync.Mutex{}
var beautify = map[string]func([]byte) []byte{
	".json": util.PrettyJson,
	".html": util.PrettyHtml,
	".js":   util.PrettyJavaScript,
}

func fileBeautify(name string, data []byte) (result []byte) {
	defer func() {
		if err := recover(); err != nil {
			result = data
		}
	}()

	var ext = filepath.Ext(name)

	extsLocker.Lock()
	exts[ext] = exts[ext] + 1
	extsLocker.Unlock()

	b, ok := beautify[ext]
	if !ok {
		return data
	}

	return b(data)
}

func parseWxid(root string) (string, error) {
	var regAppId = regexp.MustCompile(`(wx[0-9a-f]{16})`)
	
	// Try to match in the current directory name
	base := filepath.Base(root)
	if regAppId.MatchString(base) {
		return regAppId.FindStringSubmatch(base)[1], nil
	}
	
	// If not found, try parent directory
	parent := filepath.Base(filepath.Dir(root))
	if regAppId.MatchString(parent) {
		return regAppId.FindStringSubmatch(parent)[1], nil
	}
	
	// For macOS, try to extract from the full path
	if runtime.GOOS == "darwin" {
		fullPath := root
		matches := regAppId.FindStringSubmatch(fullPath)
		if len(matches) > 0 {
			return matches[1], nil
		}
	}
	
	return "", errors.New("the path is not a mini program path (wxid not found)")
}

func scanFiles(root string) ([]string, error) {
	var result []string
	
	// First try to find .wxapkg files directly
	paths, err := util.GetDirAllFilePaths(root, "", ".wxapkg")
	if err == nil && len(paths) > 0 {
		return paths, nil
	}
	
	// If no files found, check for __APP__.wxapkg in subfolders
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	
	for _, dir := range dirs {
		// Skip .DS_Store and non-directory items
		if dir.Name() == ".DS_Store" || !dir.IsDir() {
			continue
		}
		
		subPath := filepath.Join(root, dir.Name(), "__APP__.wxapkg")
		if _, err := os.Stat(subPath); err == nil {
			result = append(result, subPath)
		}
	}
	
	if len(result) == 0 {
		return nil, errors.New(fmt.Sprintf("no '.wxapkg' file found in '%s'", root))
	}
	
	return result, nil
}

func decryptFile(wxid, wxapkgPath string) []byte {
	color.Cyan("Decrypting file: %s with wxid: %s", wxapkgPath, wxid)
	
	dataByte, err := os.ReadFile(wxapkgPath)
	if err != nil {
		color.Red("Error reading file: %v", err)
		return nil
	}

	color.Cyan("File size: %d bytes", len(dataByte))
	
	if len(dataByte) < 50 { // Minimum size check
		color.Red("File is too small to be a valid wxapkg file (%d bytes)", len(dataByte))
		return nil
	}

	// Try to detect if this is already a valid wxapkg file (not encrypted)
	if len(dataByte) >= 2 && dataByte[0] == 0xBE && dataByte[1] == 0xED {
		color.Cyan("File appears to already be in wxapkg format (BE ED markers found)")
		return dataByte
	}

	// First try standard decryption
	originData := tryStandardDecrypt(wxid, dataByte)
	
	// Check if decryption succeeded by looking for BE ED markers
	if len(originData) >= 2 && originData[0] == 0xBE && originData[1] == 0xED {
		color.Cyan("Standard decryption succeeded, found BE ED markers")
		return originData
	}
	
	// If that didn't work, try macOS-specific decryption
	color.Cyan("Standard decryption didn't produce valid markers, trying macOS-specific method")
	
	// macOS may use a different decryption method or no encryption at all
	// Let's try different possible formats:
	
	// 1. No decryption, just return the file as is
	if dataByte[0] == 0xBE && dataByte[5] == 0xED {
		color.Cyan("File appears to be in BE...ED format (not encrypted)")
		return dataByte
	}
	
	// 2. Try with no header bytes (start from 0)
	if len(dataByte) > 6 {
		testData := dataByte
		if testData[0] == 0xBE && testData[5] == 0xED {
			color.Cyan("File is valid wxapkg with BE...ED format (no decryption needed)")
			return testData
		}
	}
	
	// 3. Try with 1-6 byte offset
	for offset := 1; offset <= 6; offset++ {
		if len(dataByte) > offset+5 && dataByte[offset] == 0xBE && dataByte[offset+5] == 0xED {
			color.Cyan("Found BE...ED markers at offset %d, returning data from that point", offset)
			return dataByte[offset:]
		}
	}
	
	// If we get here, we couldn't find valid markers. Just return the data as is
	// and let the unpack function handle error detection
	color.Yellow("Warning: Couldn't find valid BE...ED markers in the file")
	
	// As a last resort, return the original file 
	return dataByte
}

// Original standard decryption method for Windows
func tryStandardDecrypt(wxid string, dataByte []byte) []byte {
	// Check if it has enough bytes for standard decryption
	if len(dataByte) < 1030 { // 6 + 1024 bytes minimum
		return dataByte // Not enough bytes, return as is
	}

	salt := "saltiest"
	iv := "the iv: 16 bytes"
	
	dk := pbkdf2.Key([]byte(wxid), []byte(salt), 1000, 32, sha1.New)
	block, _ := aes.NewCipher(dk)
	blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
	originData := make([]byte, 1024)
	blockMode.CryptBlocks(originData, dataByte[6:1024+6])

	afData := make([]byte, len(dataByte)-1024-6) // remove first 6 + 1024 byte
	var xorKey = byte(0x66)
	if len(wxid) >= 2 {
		xorKey = wxid[len(wxid)-2]
	}
	for i, b := range dataByte[1024+6:] { // from 6 + 1024 byte
		afData[i] = b ^ xorKey
	}

	originData = append(originData[:1023], afData...)
	color.Cyan("Decrypted data size: %d bytes", len(originData))
	
	// Display first few bytes for debugging
	if len(originData) >= 10 {
		firstBytes := fmt.Sprintf("% x", originData[:10])
		color.Cyan("First 10 bytes: %s", firstBytes)
	}

	return originData
}

func init() {
	RootCmd.AddCommand(unpackCmd)

	var homeDir, _ = os.UserHomeDir()
	var defaultRoot string
	
	if runtime.GOOS == "darwin" {
		// macOS path for WeChat Files
		defaultRoot = filepath.Join(homeDir, "Library/Containers/com.tencent.xinWeChat/Data/.wxapplet/packages/")
	} else {
		// Windows path (default)
		defaultRoot = filepath.Join(homeDir, "Documents/WeChat Files/Applet", "wx00000000000000")
	}

	unpackCmd.Flags().StringP("root", "r", "", "the mini progress path you want to decrypt, see: "+defaultRoot)
	unpackCmd.Flags().StringP("output", "o", "unpack", "the output path to save result")
	unpackCmd.Flags().IntP("thread", "n", 30, "the thread number")
	_ = unpackCmd.MarkFlagRequired("root")
}
