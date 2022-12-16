package request

/*
Element represents the different elements of a request that can be matched.

The Element type is used to specify which element of a request should be matched
when analyzing the request for threats. It can be one of the following values:

- Path: specifies the request path as the element to match
- Headers: specifies the request headers as the element to match
- Body: specifies the request body as the element to match
*/
type Element int

const (
    // Path specifies the request path as the request element to match.
    Path Element = iota

    // Headers specifies the request headers as the request element to match.
    Headers

    // Body specifies the request body as the request element to match.
    Body
)
