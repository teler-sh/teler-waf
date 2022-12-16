package request

type Element int

const (
    // Path specifies the request path as the request element to match.
    Path Element = iota

    // Headers specifies the request headers as the request element to match.
    Headers

    // Body specifies the request body as the request element to match.
    Body
)
