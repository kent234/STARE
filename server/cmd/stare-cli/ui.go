package main

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

var logMutex sync.Mutex
var useColor = true

const (
	reset        = "\033[0m"
	dim          = "\033[2m"
	blink        = "\033[5m"
	green        = "\033[32m"
	brightGreen  = "\033[92m"
	brightCyan   = "\033[96m"
	brightYellow = "\033[93m"
	brightRed    = "\033[91m"
	brightWhite  = "\033[97m"

	altScreenOn  = "\033[?1049h"
	altScreenOff = "\033[?1049l"
)

func colorize(text, color string) string {
	if !useColor {
		return text
	}
	return color + text + reset
}

func enterAltScreen() {
	if useColor {
		fmt.Print(altScreenOn)
	}
}

func exitAltScreen() {
	if useColor {
		fmt.Print(altScreenOff)
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J\033[3J")
}

func hideCursor() { fmt.Print("\033[?25l") }
func showCursor() { fmt.Print("\033[?25h") }

func Typewriter(text string, speed time.Duration) {
	for _, char := range text {
		fmt.Printf("%c", char)
		time.Sleep(speed)
	}
	fmt.Println()
}

func MatrixRain(duration time.Duration) {
	width, height := 80, 20
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;':\",./<>?")
	frames := int(duration / (50 * time.Millisecond))

	hideCursor()
	defer showCursor()

	for f := 0; f < frames; f++ {
		fmt.Print("\033[H")
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				if rand.Intn(10) > 7 {
					fmt.Print(colorize(string(chars[rand.Intn(len(chars))]), green))
				} else if rand.Intn(100) > 95 {
					fmt.Print(colorize(string(chars[rand.Intn(len(chars))]), brightWhite))
				} else {
					fmt.Print(" ")
				}
			}
			fmt.Println()
		}
		time.Sleep(50 * time.Millisecond)
	}
	clearScreen()
}

func printRawBanner(glitchFrame int) {
	banner := []string{
		`███████╗████████╗ █████╗ ██████╗ ███████╗`,
		`██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝`,
		`███████╗   ██║   ███████║██████╔╝█████╗  `,
		`╚════██║   ██║   ██╔══██║██╔══██╗██╔══╝  `,
		`███████║   ██║   ██║  ██║██║  ██║███████╗`,
		`╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝`,
	}

	fmt.Println()
	for _, line := range banner {
		out := ""
		for _, char := range line {
			if glitchFrame >= 0 && rand.Intn(100) > 80 {
				out += colorize(string(rune(33+rand.Intn(94))), brightRed)
			} else {
				out += colorize(string(char), brightGreen)
			}
		}
		fmt.Println("  " + out)
	}
	fmt.Println()
	fmt.Println(colorize("  [ SYSTEM: SURFACE TRACKING AND RECON ENGINE ]", brightCyan))
	fmt.Println(colorize("  [ STATUS: ARMED AND READY ]", brightYellow))
	fmt.Println(colorize("  [ WARNING: AUTHORIZED TARGETS ONLY ]", brightRed))
	fmt.Println()
}

func GlitchBanner() {
	frames := 10
	for i := 0; i < frames; i++ {
		clearScreen()
		printRawBanner(i)
		time.Sleep(50 * time.Millisecond)
	}
	clearScreen()
	printRawBanner(-1)
}

func PrintHelp() {
	fmt.Println(colorize("  ╔════════════════════════════════════════════════════════════╗", brightCyan))
	fmt.Println(colorize("  ║                      S.T.A.R.E GUIDE                       ║", brightWhite))
	fmt.Println(colorize("  ╠════════════════════════════════════════════════════════════╣", brightCyan))
	fmt.Println(colorize("  ║ ", brightCyan) + "1. Введи домен (example.com) или IP (8.8.8.8)             " + colorize(" ║", brightCyan))
	fmt.Println(colorize("  ║ ", brightCyan) + "2. Выбери модули цифрами через запятую (например: 1,3,5)   " + colorize(" ║", brightCyan))
	fmt.Println(colorize("  ║ ", brightCyan) + "   или напиши 'all', чтобы запустить полный спектр.        " + colorize(" ║", brightCyan))
	fmt.Println(colorize("  ║ ", brightCyan) + "3. Нажми Enter и жди отчет.                               " + colorize(" ║", brightCyan))
	fmt.Println(colorize("  ║ ", brightCyan) + "4. Для выхода введи 'exit' или 'quit' вместо цели.         " + colorize(" ║", brightCyan))
	fmt.Println(colorize("  ╚════════════════════════════════════════════════════════════╝", brightCyan))
	fmt.Println()
}

type Spinner struct {
	stop chan bool
	mu   sync.Mutex
}

func NewSpinner(msg string) *Spinner {
	s := &Spinner{stop: make(chan bool)}
	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Printf("\r\033[K")
				return
			default:
				s.mu.Lock()
				fmt.Printf("\r  %s %s", colorize(frames[i%len(frames)], brightCyan), msg)
				s.mu.Unlock()
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
	return s
}

func (s *Spinner) Stop() {
	s.stop <- true
}

func BoxedText(title string) {
	line := strings.Repeat("═", len(title)+6)
	fmt.Println()
	fmt.Println(colorize("  ╔"+line+"╗", brightCyan))
	fmt.Println(colorize("  ║   "+title+"   ║", brightWhite))
	fmt.Println(colorize("  ╚"+line+"╝", brightCyan))
}

func LogInfo(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Printf("\r\033[K  %s %s\n", colorize("[*]", brightCyan), msg)
}

func LogSuccess(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Printf("\r\033[K  %s %s\n", colorize("[+]", brightGreen), msg)
}

func LogWarn(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Printf("\r\033[K  %s %s\n", colorize("[!]", brightYellow), msg)
}

func LogError(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Printf("\r\033[K  %s %s\n", colorize("[-]", brightRed), msg)
}
