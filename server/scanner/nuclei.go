//go:build nuclei

package scanner

import (
	"context"
	"fmt"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type NucleiFinding struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	MatchedAt  string `json:"matched_at"`
}

// RunNuclei запускает сканирование Nuclei с фильтром по критическим и высоким уязвимостям.
func RunNuclei(ctx context.Context, target string) ([]NucleiFinding, error) {
	var findings []NucleiFinding
	var mu sync.Mutex

	opts := []nuclei.NucleiEngineOption{
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity: envOr("NUCLEI_SEVERITY", "critical,high"),
		}),
	}
	if dir := envOr("NUCLEI_TEMPLATES", ""); dir != "" {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{dir},
		}))
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("nuclei engine init: %w", err)
	}
	defer ne.Close()

	// Загружаем цель
	ne.LoadTargets([]string{target}, false)

	// Запускаем с колбэком для сбора результатов
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()

		findings = append(findings, NucleiFinding{
			TemplateID: event.TemplateID,
			Name:       event.Info.Name,
			Severity:   event.Info.SeverityHolder.Severity.String(),
			MatchedAt:  event.Matched,
		})
	})

	if err != nil {
		return nil, fmt.Errorf("nuclei execution: %w", err)
	}

	return findings, nil
}
