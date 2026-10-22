package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Включаем альтернативный экран (как в Vim)
	enterAltScreen()

	// Перехватываем Ctrl+C, чтобы красиво выйти из Alt Screen
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		exitAltScreen()
		showCursor()
		fmt.Println("\n  >> Interrupted. Stay curious.")
		os.Exit(0)
	}()

	// Этот defer сработает при обычном выходе (exit/quit)
	defer exitAltScreen()
	defer showCursor()

	clearScreen()
	MatrixRain(2 * time.Second)
	GlitchBanner()
	PrintHelp()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(colorize("  ┌─[root@stare]─[~]\n  └──╼ # ", brightGreen))
		target, _ := reader.ReadString('\n')
		target = strings.TrimSpace(target)

		if target == "" || target == "exit" || target == "quit" {
			Typewriter("\n  >> Closing connection... Goodbye.", 30*time.Millisecond)
			break
		}

		fmt.Println()
		fmt.Println(colorize("  [1] Certificates (crt.sh)", brightCyan))
		fmt.Println(colorize("  [2] DNS Resolve", brightCyan))
		fmt.Println(colorize("  [3] Wordlist Brute-force", brightCyan))
		fmt.Println(colorize("  [4] Port Scan", brightCyan))
		fmt.Println(colorize("  [all] Full Spectrum Scan", brightYellow))
		fmt.Println()

		fmt.Print(colorize("  ┌─[select modules]\n  └──╼ # ", brightGreen))
		modsInput, _ := reader.ReadString('\n')
		modsInput = strings.TrimSpace(strings.ToLower(modsInput))

		var mods []ModuleID
		if modsInput == "all" || modsInput == "*" {
			mods = []ModuleID{ModCerts, ModDNS, ModWordlist, ModPorts}
		} else {
			if strings.Contains(modsInput, "1") {
				mods = append(mods, ModCerts)
			}
			if strings.Contains(modsInput, "2") {
				mods = append(mods, ModDNS)
			}
			if strings.Contains(modsInput, "3") {
				mods = append(mods, ModWordlist)
			}
			if strings.Contains(modsInput, "4") {
				mods = append(mods, ModPorts)
			}
		}

		if len(mods) == 0 {
			LogWarn("No modules selected. Aborting.")
			continue
		}

		fmt.Println()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

		// Запускаем фейковые логи в фоне
		go fakeLogs(ctx, target)

		result := runScan(ctx, target, mods)
		cancel()

		fmt.Println()
		printResults(result)
		fmt.Println()

		Typewriter("  Press ENTER to continue...", 10*time.Millisecond)
		reader.ReadString('\n')
		clearScreen()
		printRawBanner(-1) // Быстрый рендер баннера без глитча при повторном входе
	}
}
