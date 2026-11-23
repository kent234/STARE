package scanner

import (
	"bytes"
	"sort"
)

// Файл стабилизирует порядок срезов, которые заполняются параллельно.
// JSON-карты Go сортирует сам, а массивы — нет; без этого повторный скан
// того же домена давал другой порядок элементов и ломал diff.

func sortObservations(items []Observation) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Source != items[j].Source {
			return items[i].Source < items[j].Source
		}
		if items[i].Confidence != items[j].Confidence {
			return items[i].Confidence < items[j].Confidence
		}
		// Payload — единственный стабильный дискриминатор внутри источника:
		// FetchedAt меняется от прогона к прогону.
		return bytes.Compare(items[i].Payload, items[j].Payload) < 0
	})
}

func sortVulnerabilities(items []NucleiFinding) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].TemplateID != items[j].TemplateID {
			return items[i].TemplateID < items[j].TemplateID
		}
		if items[i].MatchedAt != items[j].MatchedAt {
			return items[i].MatchedAt < items[j].MatchedAt
		}
		return items[i].Name < items[j].Name
	})
}

func sortHTTPProbes(items []HTTPProbe) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Input != items[j].Input {
			return items[i].Input < items[j].Input
		}
		return items[i].URL < items[j].URL
	})
}

func sortTLSInfos(items []TLSInfo) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Host != items[j].Host {
			return items[i].Host < items[j].Host
		}
		if items[i].Port != items[j].Port {
			return items[i].Port < items[j].Port
		}
		return items[i].SubjectCN < items[j].SubjectCN
	})
}

func sortThreatHits(items []ThreatHit) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Source != items[j].Source {
			return items[i].Source < items[j].Source
		}
		return items[i].Indicator < items[j].Indicator
	})
}

func sortCloudBuckets(items []CloudBucket) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Provider != items[j].Provider {
			return items[i].Provider < items[j].Provider
		}
		return items[i].Name < items[j].Name
	})
}
