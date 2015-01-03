# auth

Golang package with generic implementation of Basic HTTP authentication middleware for the following frameworks:

* [gohttp](https://github.com/gohttp/app)
* [negroni](https://github.com/codegangsta/negroni)

## gohttp example

```go
package main

import "github.com/gohttp/app"
import "github.com/gocontrib/auth"
import "net/http"
import "fmt"

func main() {
  app := app.New()

  app.Use(auth.Basic(auth.BasicConfig{
    Validate: func(r *http.Request, user, password string) bool {
      return user == "bob" && password == "b0b"
    }
  }))

  app.Get("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "hello")
  }))

  app.Listen(":3000")
}
```
