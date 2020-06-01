# byte-template

Byte Template is a templating engine for byte slices with custom directives.

```go
package main
import (
    "bytes"
    "fmt"
    "github.com/jensneuse/byte-template"
    "io"
)

func main() {
    template := byte_template.New(byte_template.DirectiveDefinition{
        Name:[]byte("toLower"),
        Resolve:func(w io.Writer, arg []byte) (n int,err error) {
            return w.Write(bytes.ToLower(arg))
        },
    })
    buf := bytes.Buffer{}
    _,_ = template.Execute(&buf,[]byte("/api/user/{{ toLower .name }}"),func(w io.Writer, path []byte) (n int,err error) {
        if bytes.Equal(path,[]byte("name")){
            _,err = w.Write([]byte("Jens"))
        }
        return      
    })
    fmt.Println(buf.String()) // Output: jens
}
```

# Contributors

- [Jens Neuse][jens-neuse-github] (Project Lead & Active Maintainer)
- [Sergey Petrunin][sergey-petrunin-github] (Project Lead & Active Maintainer)

[jens-neuse-github]: https://github.com/jensneuse
[sergey-petrunin-github]: https://github.com/spetrunin