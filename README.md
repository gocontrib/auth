[![Build Status](https://travis-ci.org/gocontrib/auth.svg?branch=master)](https://travis-ci.org/gocontrib/auth)
# auth

Golang http middleware with generic implementation of [Basic HTTP](http://en.wikipedia.org/wiki/Basic_access_authentication)
and [JWT](http://jwt.io/) authentication schemes.

### Basic auth example

```go
package main

import "github.com/gohttp/app"
import "github.com/gocontrib/auth"
import "net/http"
import "fmt"

func main() {
  app := app.New()

  app.Use(auth.Middleware(auth.Config{
    Validate: func(r *http.Request, user, password string) error {
      if user == "bob" && password == "b0b" {
        return nil
      }
      return fmt.Errorf("Invalid user name '%s' or password", user)
    }
  }))

  app.Get("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "hello")
  }))

  app.Listen(":3000")
}
```
