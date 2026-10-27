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
	// Включаем альтернативный экран (как в Vim), чтобы не засорять историю
	enterAltScreen()

	// Перехватываем Ctrl+C для корректного выхода
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		exitAltScreen()
		showCursor()
		fmt.Println("\n  >> Interrupted. Stay curious.")
		os.Exit(0)
	}()

	// Гарантированный возврат терминала в нормальное состояние при выходе
	defer exitAltScreen()
	defer showCursor()

	// Стартовая анимация
	clearScreen()
	MatrixRain(2 * time.Second)
	GlitchBanner()
	PrintHelp()

	reader := bufio.NewReader(os.Stdin)

	for {
		// Приглашение командной строки
		fmt.Print(colorize("  ┌─[root@stare]─[~]\n  └──╼ # ", brightGreen))
		target, _ := reader.ReadString('\n')
		target = strings.TrimSpace(target)

		// Выход
		if target == "" || target == "exit" || target == "quit" {
			Typewriter("\n  >> Closing connection... Goodbye.", 30*time.Millisecond)
			break
		}

		// Меню выбора модулей
		fmt.Println()
		fmt.Println(colorize("  [1] Certificates (crt.sh + crt.name + RapidDNS)", brightCyan))
		fmt.Println(colorize("  [2] Extended DNS (MX, TXT, NS)", brightCyan))
		fmt.Println(colorize("  [3] Subdomain Brute-force (5000 words)", brightCyan))
		fmt.Println(colorize("  [4] Port Scan (Main IPs)", brightCyan))
		fmt.Println(colorize("  [5] WHOIS Info", brightCyan))
		fmt.Println(colorize("  [6] Fingerprinting (Main Domain)", brightCyan))
		fmt.Println(colorize("  [7] Deep Scan (Recursive Subdomains)", brightYellow))
		fmt.Println(colorize("  [all] Full Spectrum Scan (1-7)", brightYellow))
		fmt.Println()

		fmt.Print(colorize("  ┌─[select modules]\n  └──╼ # ", brightGreen))
		modsInput, _ := reader.ReadString('\n')
		modsInput = strings.TrimSpace(strings.ToLower(modsInput))

		var mods []ModuleID
		if modsInput == "all" || modsInput == "*" {
			mods = []ModuleID{ModCerts, ModDNS, ModWordlist, ModPorts, ModWhois, ModFingerprint, ModDeepScan}
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
			if strings.Contains(modsInput, "5") {
				mods = append(mods, ModWhois)
			}
			if strings.Contains(modsInput, "6") {
				mods = append(mods, ModFingerprint)
			}
			if strings.Contains(modsInput, "7") {
				mods = append(mods, ModDeepScan)
			}
		}

		if len(mods) == 0 {
			LogWarn("No modules selected. Aborting.")
			continue
		}

		fmt.Println()
		// Даем сканированию 10 минут на случай глубокого скана
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)

		// Запускаем фейковые логи в фоне (для атмосферы)
		go fakeLogs(ctx, target)

		// Запускаем сканирование
		result := runScan(ctx, target, mods)
		cancel()

		// Выводим результаты в консоль
		fmt.Println()
		printResults(result)
		fmt.Println()

		// Сохраняем в JSON-файл
		saveReport(result)

		fmt.Println()
		Typewriter("  Press ENTER to continue...", 10*time.Millisecond)
		reader.ReadString('\n')

		// Очищаем экран для следующего запуска
		clearScreen()
		printRawBanner(-1)
	}
}
