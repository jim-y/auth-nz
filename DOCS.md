## Authorize endpoint

### Validate authorization request

- mandatory request fields
- - uri
- - method
- mandatory query fields
- - client_id
- - redirect_uri
- - state
- - response type

- to parameterize oauth properties like client_id etc..
- some way to get the query string from the request
- some way to find the client by the provided clientId
- how to find the uri/url
- how to find the method