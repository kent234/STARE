package scanner

import "os"

// init регистрирует key-based источники только при наличии соответствующего ключа,
// чтобы не засорять ScanResult.Errors при неполной конфигурации.
func init() {
	if os.Getenv("STARE_DISABLE_INTEL") == "1" {
		return
	}
	if os.Getenv("SHODAN_API_KEY") != "" {
		RegisterSource(NewShodanSource())
	}
	// GreyNoise Community отвечает и без ключа (с более строгим лимитом).
	RegisterSource(NewGreyNoiseSource())
	if os.Getenv("ABUSEIPDB_API_KEY") != "" {
		RegisterSource(NewAbuseIPDBSource())
	}
}
