package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func runCommand(cmd string) string {
	fmt.Printf("Run command: %s\n", cmd)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Printf("Error: %s\n: %s\n", err, string(out))
	}
	return string(out)
}

func checkECC() {
	fmt.Println("Checking for ecc...")
	if _, err := exec.LookPath("./ecc-aarch64"); err != nil {
		fmt.Println("Error: ecc is not found! Install it and try later.")
		os.Exit(1)
	}
}

func startEcli() {
	fmt.Println("Start eBPF with ecli, run package.json...")
	cmd := exec.Command("bash", "-c", "env PATH=$PATH ./ecli run package.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error ecli: %s\n", err)
		return
	}
	time.Sleep(2 * time.Second)
	fmt.Println("eBPF-program started!")
}

func findAndPinBPFMap() string {
	output := runCommand("bpftool map show")
	var lastMapID string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "block_path_map") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				lastMapID = strings.TrimSuffix(fields[0], ":")
			}
		}
	}

	if lastMapID == "" {
		fmt.Println("Error: Map block_path_map not found!")
		return ""
	}

	fmt.Printf("Found Map ID: %s\n", lastMapID)

	pinnedCheck := runCommand("ls /sys/fs/bpf/block_path_map 2>/dev/null")
	if pinnedCheck != "" {
		fmt.Println("Map is pinned, unpin...")
		runCommand("bpftool map unpin /sys/fs/bpf/block_path_map")
	}

	pinCmd := fmt.Sprintf("bpftool map pin id %s /sys/fs/bpf/block_path_map", lastMapID)
	runCommand(pinCmd)
	fmt.Println("Map pinned successfully!")
	return lastMapID
}

func clearBPFMap() {
	fmt.Println("Clean eBPF-map before adding new path...")
	out := runCommand("bpftool map dump pinned /sys/fs/bpf/block_path_map")
	if strings.Contains(out, "Found 0 elements") {
		fmt.Println("Map is empty, skip deletion.")
		return
	}
	runCommand("bpftool map delete pinned /sys/fs/bpf/block_path_map key hex 00 00 00 00")
}

func formatPathForBPF(path string) string {
	components := strings.Split(strings.Trim(path, "/"), "/")

	var parent, child string
	if len(components) > 1 {
		parent = components[len(components)-2]
		child = components[len(components)-1]
	} else {
		parent = ""
		child = components[0]
	}

	fmt.Printf("Formating path: parent='%s', child='%s'\n", parent, child)

	var paddedParent [64]byte
	var paddedChild [64]byte
	copy(paddedParent[:], []byte(parent))
	copy(paddedChild[:], []byte(child))

	parentHex := hex.EncodeToString(paddedParent[:])
	childHex := hex.EncodeToString(paddedChild[:])

	formatHex := func(hexStr string) string {
		var builder strings.Builder
		for i := 0; i < len(hexStr); i += 2 {
			builder.WriteString(hexStr[i:i+2] + " ")
			if (i+2)%32 == 0 {
				builder.WriteString("\\\n    ")
			}
		}
		return strings.TrimSuffix(builder.String(), " \\\n    ")
	}

	return formatHex(parentHex) + " \\\n    " + formatHex(childHex)
}

func updateBPFMap(path string) {
	clearBPFMap()

	asciiPath := formatPathForBPF(path)
	updateCmd := fmt.Sprintf(
		"bpftool map update pinned /sys/fs/bpf/block_path_map \\\n"+
			"    key hex 00 00 00 00 \\\n"+
			"    value hex \\\n    %s", asciiPath)

	fmt.Println("Exec command:")
	fmt.Println(updateCmd)
	runCommand(updateCmd)
	fmt.Println("Path added!")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./ebpf_manager <path>")
		return
	}

	path := os.Args[1]

	checkECC()

	fmt.Println("Compile eBPF with ecc...")
	runCommand("./ecc-aarch64 final.c")

	startEcli()

	fmt.Println("Find and pin Map eBPF...")
	mapID := findAndPinBPFMap()
	if mapID == "" {
		fmt.Println("Error: Map not found")
		return
	}

	fmt.Printf("Adding path to eBPF Map: %s\n", path)
	updateBPFMap(path)

	fmt.Println("Completed!")
}
