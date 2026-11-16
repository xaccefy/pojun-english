package hosttools

import "testing"

// Every tool in the catalog must have a category: an uncategorized one falls into the
// "Other" group, which makes page grouping meaningless. This test blocks new tools
// that forget it — it names the tool that has no category.
func TestEveryToolHasCategory(t *testing.T) {
	known := map[Category]bool{
		CatNetwork: true, CatWeb: true, CatDNS: true, CatCred: true,
		CatCode: true, CatPivot: true, CatOOB: true, CatExploit: true,
		CatMaterial: true, CatRuntime: true, CatMiddleware: true, CatMobile: true,
	}
	for _, tool := range catalog {
		if tool.Category == "" {
			t.Errorf("tool %s has no category", tool.Name)
			continue
		}
		if !known[tool.Category] {
			t.Errorf("tool %s has category %q which is not in the known category set", tool.Name, tool.Category)
		}
	}
}

// The category order must cover every defined category exactly once — the page
// renders by categoryOrder, so a missing category means its tools never show up.
func TestCategoryOrderCoversAll(t *testing.T) {
	seen := map[Category]bool{}
	for _, c := range categoryOrder {
		if seen[c] {
			t.Errorf("categoryOrder contains %q twice", c)
		}
		seen[c] = true
	}
	for _, c := range []Category{
		CatNetwork, CatWeb, CatDNS, CatCred, CatCode,
		CatPivot, CatOOB, CatExploit, CatMaterial, CatRuntime, CatMiddleware,
	} {
		if !seen[c] {
			t.Errorf("category %q is not in categoryOrder, the page will not show it", c)
		}
	}
}

// Every category needs a label (the page uses it directly as the group heading).
func TestEveryCategoryHasLabel(t *testing.T) {
	for _, c := range categoryOrder {
		if CategoryLabel(c) == "" || CategoryLabel(c) == "Other" {
			t.Errorf("category %q has no dedicated label (got %q)", c, CategoryLabel(c))
		}
	}
}

// Categories are not decoration: the catalog's tools should be spread across these
// 11 categories rather than all crammed into one. This assertion stops later changes
// from treating categories as ornamental.
func TestCategoriesActuallyPartitionCatalog(t *testing.T) {
	counts := map[Category]int{}
	for _, tool := range catalog {
		counts[tool.Category]++
	}
	if len(counts) < 8 {
		t.Errorf("tools are spread across only %d categories (%v); the categories are ornamental", len(counts), counts)
	}
	for _, c := range categoryOrder {
		if counts[c] == 0 {
			t.Errorf("category %q has no tools — either the category is wrong or the tools were not classified", c)
		}
	}
}
