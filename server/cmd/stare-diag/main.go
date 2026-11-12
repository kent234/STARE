// stare-diag — проверка подключённых источников без запуска полного скана.
//
// Запуск:
//
//	cd server
//	set -a && . ../.env && set +a
//	go run ./cmd/stare-diag -target example.com
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"stare/server/scanner"
)

func main() {
	target := flag.String("target", "1.1.1.1", "IP или домен для проверки источников")
	timeout := flag.Duration("timeout", 90*time.Second, "общий таймаут проверки")
	flag.Parse()

	sources := scanner.RegisteredSources()
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.Name())
	}
	sort.Strings(names)

	fmt.Println("STARE source diagnostics")
	fmt.Printf("target: %s\n", *target)
	fmt.Printf("registered sources (%d): %v\n", len(names), names)
	if len(names) == 0 {
		fmt.Println("!! ни один источник не зарегистрирован — проверьте .env / STARE_DISABLE_*")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	obs, errs := scanner.FetchAllSources(ctx, *target)
	elapsed := time.Since(start).Round(time.Millisecond)

	counts := map[string]int{}
	for _, o := range obs {
		counts[o.Source]++
	}
	srcNames := make([]string, 0, len(counts))
	for name := range counts {
		srcNames = append(srcNames, name)
	}
	sort.Strings(srcNames)

	fmt.Printf("\nobservations: %d (за %s)\n", len(obs), elapsed)
	for _, name := range srcNames {
		fmt.Printf("  %-12s %d\n", name, counts[name])
	}
	if len(obs) == 0 {
		fmt.Println("  (пусто — индикаторов по цели в фидах нет, это не ошибка)")
	}

	if _, err := json.Marshal(obs); err != nil {
		fmt.Printf("!! observations не сериализуются в JSON: %v\n", err)
		os.Exit(1)
	}

	if len(errs) > 0 {
		fmt.Println("\nerrors:")
		for _, e := range errs {
			fmt.Printf("  - %s\n", e)
		}
		os.Exit(1)
	}

	fmt.Println("\nOK: все зарегистрированные источники ответили без ошибок")
}
