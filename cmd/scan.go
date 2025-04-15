package cmd

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/wux1an/wxapkg/util"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Scan the wechat mini program",
	Example: "  " + programName + " scan -r \"D:\\WeChat Files\\Applet\\wx12345678901234\"",
	Run: func(cmd *cobra.Command, args []string) {
		root, err := cmd.Flags().GetString("root")
		if err != nil {
			color.Red("%v", err)
			return
		}

		var regAppId = regexp.MustCompile(`(wx[0-9a-f]{16})`)

		var files []os.DirEntry
		if files, err = findMiniProgramDirs(root); err != nil {
			color.Red("%v", err)
			return
		}

		var wxidInfos = make([]util.WxidInfo, 0, len(files))
		for _, file := range files {
			// Skip .DS_Store files on macOS
			if file.Name() == ".DS_Store" {
				continue
			}
			
			if !file.IsDir() || !regAppId.MatchString(file.Name()) {
				continue
			}

			var wxid = regAppId.FindStringSubmatch(file.Name())[1]
			info, err := util.WxidQuery.Query(wxid)
			info.Location = filepath.Join(root, file.Name())
			info.Wxid = wxid
			if err != nil {
				info.Error = fmt.Sprintf("%v", err)
			}

			wxidInfos = append(wxidInfos, info)
		}

		var tui = newScanTui(wxidInfos)
		if _, err := tea.NewProgram(tui, tea.WithAltScreen()).Run(); err != nil {
			color.Red("Error running program: %v", err)
			os.Exit(1)
		}

		if tui.selected == nil {
			return
		}

		// After selecting a mini program, instead of passing to unpack command,
		// let's handle the unpack operation directly
		wxid := tui.selected.Wxid
		appDir := tui.selected.Location
		output := wxid

		// Look for __APP__.wxapkg in numbered subdirectories
		var wxapkgFile string
		subDirs, err := os.ReadDir(appDir)
		if err != nil {
			color.Red("Error reading directory: %v", err)
			return
		}

		for _, subDir := range subDirs {
			if !subDir.IsDir() || subDir.Name() == ".DS_Store" {
				continue
			}
			
			// Check for __APP__.wxapkg in this subdirectory
			testPath := filepath.Join(appDir, subDir.Name(), "__APP__.wxapkg")
			if _, err := os.Stat(testPath); err == nil {
				wxapkgFile = testPath
				break
			}
		}

		if wxapkgFile == "" {
			color.Red("Could not find __APP__.wxapkg in any subdirectory of %s", appDir)
			return
		}

		color.Cyan("Found wxapkg file: %s", wxapkgFile)
		
		// Decrypt and unpack the file
		decryptedData := decryptFile(wxid, wxapkgFile)
		disableBeautify, _ := cmd.Flags().GetBool("disable-beautify")
		fileCount, err := unpack(decryptedData, output, 30, !disableBeautify)
		if err != nil {
			color.Red("Error unpacking: %v", err)
			return
		}
		
		color.Yellow("Unpacked %d files to %s", fileCount, output)
		
		// Save detail info
		detailFilePath := filepath.Join(output, "detail.json")
		_ = os.WriteFile(detailFilePath, []byte(tui.selected.Json()), 0600)
		color.Cyan("Saved detail info to %s", detailFilePath)
	},
}

func init() {
	RootCmd.AddCommand(scanCmd)

	var homeDir, _ = os.UserHomeDir()
	var defaultRoot string
	
	if runtime.GOOS == "darwin" {
		// macOS path for WeChat Files
		defaultRoot = filepath.Join(homeDir, "Library/Containers/com.tencent.xinWeChat/Data/.wxapplet/packages/")
	} else {
		// Windows path (default)
		defaultRoot = filepath.Join(homeDir, "Documents/WeChat Files/Applet")
	}

	scanCmd.Flags().StringP("root", "r", defaultRoot, "the mini app path")
	scanCmd.Example = fmt.Sprintf("  %s scan -r \"%s\"", programName, defaultRoot)
}

// Function to find mini program directories based on platform
func findMiniProgramDirs(root string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	
	// On macOS, we need to check for mini program directories containing __APP__.wxapkg
	if runtime.GOOS == "darwin" {
		var validDirs []os.DirEntry
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == ".DS_Store" {
				continue
			}
			
			// Check if this directory has mini program structure
			subDirs, err := os.ReadDir(filepath.Join(root, entry.Name()))
			if err != nil {
				continue
			}
			
			// Look for __APP__.wxapkg in subdirectories
			for _, subDir := range subDirs {
				if !subDir.IsDir() {
					continue
				}
				
				appPath := filepath.Join(root, entry.Name(), subDir.Name(), "__APP__.wxapkg")
				if _, err := os.Stat(appPath); err == nil {
					validDirs = append(validDirs, entry)
					break
				}
			}
		}
		return validDirs, nil
	}
	
	return entries, nil
}
