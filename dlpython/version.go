package python

import (
	"sort"
	"strconv"
	"strings"
)

func selectLatestVersion(versions []string) string {
	// Sort the versions based on a custom comparison function
	sort.Slice(versions, func(i, j int) bool {
		// Split the version numbers into components (e.g., "3.5" -> ["3", "5"])
		versionI := strings.Split(versions[i], ".")
		versionJ := strings.Split(versions[j], ".")

		// Compare each component (major, minor, etc.) as integers
		for x := 0; x < len(versionI) && x < len(versionJ); x++ {
			// Convert the components to integers for comparison
			numI, _ := strconv.Atoi(versionI[x])
			numJ, _ := strconv.Atoi(versionJ[x])

			if numI != numJ {
				return numI < numJ
			}
		}
		// If all compared components are the same, the shorter version is considered smaller
		return len(versionI) < len(versionJ)
	})

	// The latest version will be the last element after sorting
	return versions[len(versions)-1]
}
