def main():
    Printf("Hello from Starlark\n")

    header.Set("X-UDG-Starlark", "Hello from the first-ever UDG plugin")

    getResult = json.Get(graphql_request.Variables, "name")
    header.Set("X-UDG-Variable", ToUpper(Sprintf("Hello, %s!", getResult[0])))

    data = rw.Bytes()

    addition = bytes("{\"agata\": \"is the best\"}")
    result = json.Set(data, addition, "data", "country", "modification")

    rw.Reset()
    rw.Write(result)

main()