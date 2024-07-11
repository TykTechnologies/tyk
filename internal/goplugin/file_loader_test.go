package goplugin

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExist(t *testing.T) {
	storage := FileSystemStorage{}

	testCases := []struct {
		name      string
		fileFound bool
		fileName  string
	}{
		{
			name:      "file not found",
			fileFound: false,
			fileName:  "anyfile.txt1",
		},
		{
			name:      "file found",
			fileFound: true,
			fileName:  "anyfile.txt1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fileFound {
				// only create the file if it's should be found
				f, err := os.CreateTemp("", "sample")
				if err != nil {
					log.Fatal(err)
				}
				tc.fileName = f.Name()
				defer os.Remove(f.Name())
			}

			fileFound := storage.fileExist(tc.fileName)

			assert.Equal(t, tc.fileFound, fileFound)
		})
	}
}
