package mock

type Document struct {
	Tags []Tag

	Data1 []Tag
	Data2 []Tag
	Data3 []Tag
	Data4 []Tag
	Data5 []Tag
	Data6 []Tag
	Data7 []Tag
	Data8 []Tag
}

type Tag struct {
	Name string
}

//go:noinline
func NewDocument() *Document {
	return &Document{
		Tags:  make([]Tag, 0, 256),
		Data1: make([]Tag, 0, 256),
		Data2: make([]Tag, 0, 256),
		Data3: make([]Tag, 0, 256),
		Data4: make([]Tag, 0, 256),
		Data5: make([]Tag, 0, 256),
		Data6: make([]Tag, 0, 256),
		Data7: make([]Tag, 0, 256),
		Data8: make([]Tag, 0, 256),
	}
}

func (d *Document) Reset() {
	d.Tags = d.Tags[:0]

	d.Data1 = d.Data1[:0]
	d.Data2 = d.Data2[:0]
	d.Data3 = d.Data3[:0]
	d.Data4 = d.Data4[:0]
	d.Data5 = d.Data5[:0]
	d.Data6 = d.Data6[:0]
	d.Data7 = d.Data7[:0]
	d.Data8 = d.Data8[:0]
}
