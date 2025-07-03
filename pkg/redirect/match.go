package redirect

import "slices"

// Helper for matching status codes
func matchCodes(c int, awd []int) bool {
	if len(awd) == 0 {
		return true
	}
	return slices.Contains(awd, c)
}
